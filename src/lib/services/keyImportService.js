'use strict';

const sjcl = require('sjcl');
const envelope = require('../utils/keyImportEnvelope');
const privateKeyTypeEnum = require('../enumerations/privateKeyType');
const sharingTypeEnum = require('../enumerations/sharingType');
const {CURVE} = require('../enumerations/curve');

/**
 * Which algorithm name a package's curve travels under on the ticket, on the node's
 * /v1/keys/import request and inside the envelope binding.
 */
const ALGORITHM_BY_CURVE = {
    [CURVE.SECP256K1]: envelope.ALGORITHM.ECDSA,
    [CURVE.ED25519]: envelope.ALGORITHM.EDDSA,
};

class KeyImportService {

    /**
     * Opens every key part the ticket asks for and re-seals it, one at a time, to the node that
     * owns that seat.
     *
     * THIS IS THE WHOLE CEREMONY-SIDE OPERATION, ON PURPOSE. The parts are decrypted and
     * re-sealed inside this one call: no plaintext point is returned, stored, or handed across
     * an IPC boundary, and recoverPrivateKey is never called, so the group secret is not formed
     * even for an instant. What comes back is ciphertext addressed to the nodes plus the public
     * bookkeeping the client needs to see.
     *
     * @param {object} ticket the key-import ticket downloaded from the Dashboard
     * @param {RecoveryDataEntity} recoveryData the client's backup package
     * @param {Buffer} privateKeyBuffer the client's RSA private key file, as read from disk
     * @param {string} privateKeyType
     * @param {string|null} password
     * @return {{vaultId: string, kind: string, algorithm: string, keyId: string,
     *           sealedParts: {algorithm: string, index: number, senderPublicKey: string,
     *           payload: string}[], sealedSeats: number[], seatsWithoutAPart: number[]}}
     */
    sealKeyParts(ticket, recoveryData, privateKeyBuffer, privateKeyType, password = null) {
        let rsaPrivateKey;
        try {
            rsaPrivateKey = privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED)
                ? sjcl.decrypt(password, privateKeyBuffer.toString())
                : privateKeyBuffer.toString();
        } catch (e) {
            throw new Error("Invalid password!");
        }

        const curve = recoveryData.getCurve();
        const algorithm = ALGORITHM_BY_CURVE[curve];
        if (!algorithm) {
            throw new Error(`The backup package is on an unsupported curve: ${curve}`);
        }

        // Lagrange interpolation of the imported points is what rebuilds the group secret inside
        // the ceremony. An additive or multiplicative package's parts are not polynomial points,
        // so importing them would not fail - it would silently rebuild a different key.
        if (recoveryData.getSharingType() !== sharingTypeEnum.SHAMIR) {
            throw new Error(
                `Only a ${sharingTypeEnum.SHAMIR} backup package can be imported, this one is `
                + `${recoveryData.getSharingType()}`
            );
        }

        const metadata = this._findSessionMetadata(ticket, algorithm);
        const isRecovery = ticket.kind === envelope.KIND.RECOVERY;

        // The retired chain code and the retired group public key both come from the package,
        // which is why the ticket carries neither. On a recovery each node re-reads them from
        // its own stored row and the envelope dies on the GCM tag if they disagree.
        const chainCode = recoveryData.recoverChainCode(rsaPrivateKey);
        const publicKey = isRecovery ? recoveryData.getCompressedPublicKey() : undefined;
        const oldThreshold = isRecovery ? metadata.oldThreshold : 0;

        const sealedParts = [];
        const seatsWithoutAPart = [];
        for (const index of this._seats(metadata)) {
            const part = recoveryData.getKeyPart(index);
            if (part === null) {
                seatsWithoutAPart.push(index);

                continue;
            }

            const point = part
                .recoverKeyShare(rsaPrivateKey, curve)
                .toArrayLike(Buffer, 'be', envelope.POINT_BYTES_LENGTH);

            let sealed;
            try {
                sealed = envelope.sealPoint({
                    point: point,
                    recipientPublicKey: metadata.players[index],
                    sessionId: metadata.sessionId,
                    binding: {
                        kind: ticket.kind,
                        keyId: metadata.keyId,
                        oldKeyId: isRecovery ? metadata.oldKeyId : undefined,
                        algorithm: algorithm,
                        importerIndex: index,
                        newThreshold: metadata.threshold,
                        oldThreshold: oldThreshold,
                        publicKey: publicKey,
                        chainCode: chainCode,
                    },
                });
            } finally {
                // The point stops existing here whatever happened: it is the one value in this
                // function that must never outlive the seal.
                point.fill(0);
            }

            sealedParts.push({
                algorithm: algorithm,
                index: index,
                senderPublicKey: sealed.senderPublicKey,
                payload: sealed.payload,
            });
        }

        this._assertEnoughParts(sealedParts, seatsWithoutAPart, isRecovery, oldThreshold);

        return {
            vaultId: ticket.vaultId,
            kind: ticket.kind,
            algorithm: algorithm,
            keyId: metadata.keyId,
            sealedParts: sealedParts,
            sealedSeats: sealedParts.map(part => part.index),
            seatsWithoutAPart: seatsWithoutAPart,
        };
    }

    /**
     * @param {object} ticket
     * @param {string} algorithm
     * @return {object}
     * @private
     */
    _findSessionMetadata(ticket, algorithm) {
        const metadata = ticket.keyImportMetadata.find(session => session.algorithm === algorithm);
        if (metadata === undefined) {
            throw new Error(`The ticket has no ${algorithm} session - it was issued for another key`);
        }

        if (!metadata.sessionId) {
            throw new Error(
                `The ${algorithm} session of the ticket carries no sessionId, so its parts cannot `
                + `be sealed to anything`
            );
        }

        return metadata;
    }

    /**
     * The seats the ticket asks for, ascending, so the sealed file reads in seat order whatever
     * order the ticket's map came in.
     *
     * @param {object} metadata
     * @return {number[]}
     * @private
     */
    _seats(metadata) {
        return Object.keys(metadata.players)
            .map(index => Number(index))
            .sort((left, right) => left - right);
    }

    /**
     * A ceremony short of parts does not fail honestly today - it interpolates a different
     * polynomial and rebuilds a different key - so a package that cannot cover the retired
     * sharing is refused here, before anything is sealed to a node.
     *
     * @param {object[]} sealedParts
     * @param {number[]} seatsWithoutAPart
     * @param {boolean} isRecovery
     * @param {number} oldThreshold
     * @private
     */
    _assertEnoughParts(sealedParts, seatsWithoutAPart, isRecovery, oldThreshold) {
        if (sealedParts.length === 0) {
            throw new Error(
                "The backup package holds no part for any seat in the ticket. A package whose "
                + "parts carry no player index - the shared/ERS format - cannot be used for a "
                + "key import, because a part's seat cannot be identified from its position."
            );
        }

        if (isRecovery && sealedParts.length < oldThreshold) {
            throw new Error(
                `The ceremony needs ${oldThreshold} parts and the backup package covers only `
                + `${sealedParts.length} of the ticket's seats (missing `
                + `${seatsWithoutAPart.join(', ')})`
            );
        }
    }
}

module.exports = KeyImportService;
