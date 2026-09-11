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

/**
 * How long the hex of a compressed group public key is, per algorithm: twice the byte length
 * the binding is defined over, which is also the cap the node's api puts on the field.
 */
const EXTERNAL_PUBLIC_KEY_HEX_LENGTH = {
    [envelope.ALGORITHM.ECDSA]: envelope.RETIRED_PUBLIC_KEY_BYTES_LENGTH[envelope.ALGORITHM.ECDSA] * 2,
    [envelope.ALGORITHM.EDDSA]: envelope.RETIRED_PUBLIC_KEY_BYTES_LENGTH[envelope.ALGORITHM.EDDSA] * 2,
};

const HEX = /^([0-9a-fA-F]{2})+$/;

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
     * The ticket is checked in full BEFORE the RSA key is opened and before anything is sealed.
     * Every refusal below is a ceremony that cannot succeed, and the client finds out here, in
     * a sentence naming the file to fix, rather than from a node an hour later.
     *
     * @param {object} ticket the key-import ticket downloaded from the Dashboard
     * @param {RecoveryDataEntity} recoveryData the client's backup package
     * @param {Buffer} privateKeyBuffer the client's RSA private key file, as read from disk
     * @param {string} privateKeyType
     * @param {string|null} password
     * @return {{vaultId: string, kind: string, algorithm: string, keyId: string,
     *           declaredPublicKey: string|null,
     *           sealedParts: {algorithm: string, index: number, senderPublicKey: string,
     *           payload: string}[], sealedSeats: number[]}}
     */
    sealKeyParts(ticket, recoveryData, privateKeyBuffer, privateKeyType, password = null) {
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

        const kind = this._readKind(ticket);
        const isRecovery = kind === envelope.KIND.RECOVERY;
        const metadata = this._findSessionMetadata(ticket, algorithm, isRecovery);
        const seats = this._seats(metadata, algorithm);
        this._assertPackageCoversTheTicket(recoveryData, seats, isRecovery, metadata.oldThreshold);

        // Where the two bound values that describe the key itself come from, and they come from
        // different places per kind:
        //
        //   recovery   both are the package's. Each node re-reads them from its OWN stored row
        //              for the retired key - the one check in the path that is not being asked
        //              of the same caller who supplies the parts - and the envelope dies on the
        //              GCM tag if what the package holds disagrees.
        //   migration  there is no such row to read, so the values were declared once when the
        //              import was initialized and echoed back on the ticket. The node binds the
        //              chain code it was handed, so the tool must bind the SAME one, and the
        //              retired public key is not part of a migration binding at all.
        const externalKey = isRecovery ? null : this._findExternalKey(ticket, algorithm, recoveryData);
        const publicKey = isRecovery ? recoveryData.getCompressedPublicKey() : undefined;
        const oldThreshold = isRecovery ? metadata.oldThreshold : 0;

        let rsaPrivateKey;
        try {
            rsaPrivateKey = privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED)
                ? sjcl.decrypt(password, privateKeyBuffer.toString())
                : privateKeyBuffer.toString();
        } catch (e) {
            throw new Error("Invalid password!");
        }

        const chainCode = isRecovery
            ? recoveryData.recoverChainCode(rsaPrivateKey)
            : externalKey.chainCode;

        const sealedParts = [];
        for (const index of seats) {
            const point = this._openKeyPart(recoveryData, index, rsaPrivateKey, curve);

            let sealed;
            try {
                sealed = envelope.sealPoint({
                    point: point,
                    recipientPublicKey: metadata.players[index],
                    sessionId: metadata.sessionId,
                    binding: {
                        kind: kind,
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

        return {
            vaultId: ticket.vaultId,
            kind: kind,
            algorithm: algorithm,
            keyId: metadata.keyId,
            // Public, and worth showing: on a migration this is the key the nodes will be told
            // they imported, so the client can read it back against the key they meant to bring.
            declaredPublicKey: externalKey === null ? null : externalKey.publicKey,
            sealedParts: sealedParts,
            sealedSeats: sealedParts.map(part => part.index),
        };
    }

    /**
     * The kind decides what the node is required to hold and is the first element of the
     * binding, so an unrecognised one cannot be treated as "probably a migration" - that is the
     * path with no anchor to check against.
     *
     * @param {object} ticket
     * @return {string}
     * @private
     */
    _readKind(ticket) {
        const kind = ticket.kind;
        if (kind !== envelope.KIND.RECOVERY && kind !== envelope.KIND.MIGRATION) {
            throw new Error(
                `The ticket says this import is "${kind}", which this tool does not know how to `
                + `seal for. Download the ticket again from the Dashboard - a valid one says `
                + `either "${envelope.KIND.RECOVERY}" or "${envelope.KIND.MIGRATION}".`
            );
        }

        return kind;
    }

    /**
     * @param {object} ticket
     * @param {string} algorithm
     * @param {boolean} isRecovery
     * @return {object}
     * @private
     */
    _findSessionMetadata(ticket, algorithm, isRecovery) {
        const sessions = Array.isArray(ticket.keyImportMetadata) ? ticket.keyImportMetadata : [];
        const metadata = sessions.find(session => session.algorithm === algorithm);
        if (metadata === undefined) {
            throw new Error(`The ticket has no ${algorithm} session - it was issued for another key`);
        }

        // The envelope key is HKDF over the ECDH secret with the session id in the info
        // parameter, so a part sealed without it - or against a different one - simply does not
        // open at the node. There is nothing to fall back on and nothing to invent here.
        if (typeof metadata.sessionId !== 'string' || !HEX.test(metadata.sessionId)) {
            throw new Error(
                `The ${algorithm} session of the ticket carries no sessionId, so its parts cannot `
                + `be sealed to anything. Start the import again in the Dashboard and download `
                + `the new ticket.`
            );
        }

        if (typeof metadata.keyId !== 'string' || metadata.keyId.length === 0) {
            throw new Error(
                `The ${algorithm} session of the ticket names no key to import into. Download the `
                + `ticket again from the Dashboard.`
            );
        }

        if (!Number.isInteger(metadata.threshold) || metadata.threshold < 1) {
            throw new Error(
                `The ${algorithm} session of the ticket declares no threshold for the new key. `
                + `Download the ticket again from the Dashboard.`
            );
        }

        if (isRecovery) {
            if (typeof metadata.oldKeyId !== 'string' || metadata.oldKeyId.length === 0) {
                throw new Error(
                    `The ${algorithm} session of the ticket does not say which key is being `
                    + `restored. Download the ticket again from the Dashboard.`
                );
            }

            // 0 is what every row the pre-fix importer wrote carries, and it means "unknown",
            // never "matches"; a node refuses the import on it.
            if (!Number.isInteger(metadata.oldThreshold) || metadata.oldThreshold < 1) {
                throw new Error(
                    `The ${algorithm} session of the ticket does not say how many parts the `
                    + `retired key needed. Download the ticket again from the Dashboard.`
                );
            }
        }

        return metadata;
    }

    /**
     * The seats the ticket asks for, ascending, so the sealed file reads in seat order whatever
     * order the ticket's map came in.
     *
     * A seat whose node public key is missing cannot be sealed to: there is no second place to
     * look it up, and going ahead would leave that node with nothing to import.
     *
     * @param {object} metadata
     * @param {string} algorithm
     * @return {number[]}
     * @private
     */
    _seats(metadata, algorithm) {
        const players = metadata.players;
        if (players === null || typeof players !== 'object' || Object.keys(players).length === 0) {
            throw new Error(
                `The ${algorithm} session of the ticket names no players, so there is no node to `
                + `seal anything to. Download the ticket again from the Dashboard.`
            );
        }

        const seats = [];
        const withoutAPublicKey = [];
        for (const key of Object.keys(players)) {
            const index = Number(key);
            if (!Number.isInteger(index) || index < 0) {
                throw new Error(
                    `The ${algorithm} session of the ticket names a seat that is not a player `
                    + `number ("${key}"). Download the ticket again from the Dashboard.`
                );
            }

            if (typeof players[key] !== 'string' || players[key].length === 0) {
                withoutAPublicKey.push(index);
            }

            seats.push(index);
        }

        if (withoutAPublicKey.length) {
            throw new Error(
                `The ticket gives no public key for ${this._seatList(withoutAPublicKey)}, so that `
                + `part cannot be locked for its node. Download the ticket again from the `
                + `Dashboard, and if it is still incomplete, reset the import and start it over.`
            );
        }

        return seats.sort((left, right) => left - right);
    }

    /**
     * The key a migration brings in, as it was declared when the import was initialized and
     * echoed back on the ticket. It is required there - a node has no row to read it from - and
     * the chain code of it is what the node binds, so this is the value the tool must seal
     * against rather than one the client types a second time.
     *
     * @param {object} ticket
     * @param {string} algorithm
     * @param {RecoveryDataEntity} recoveryData
     * @return {{algorithm: string, chainCode: string, publicKey: string}}
     * @private
     */
    _findExternalKey(ticket, algorithm, recoveryData) {
        const declared = Array.isArray(ticket.externalKeys) ? ticket.externalKeys : [];
        const externalKey = declared.find(key => key.algorithm === algorithm);
        if (externalKey === undefined) {
            throw new Error(
                `This is a migration, but the ticket does not say which ${algorithm} key is being `
                + `brought in. Start the import again in the Dashboard and give the key's chain `
                + `code and public key there.`
            );
        }

        if (typeof externalKey.chainCode !== 'string' || !HEX.test(externalKey.chainCode)) {
            throw new Error(
                `The ${algorithm} key on the ticket has no usable chain code. Start the import `
                + `again in the Dashboard and check the chain code you give it.`
            );
        }

        const expectedLength = EXTERNAL_PUBLIC_KEY_HEX_LENGTH[algorithm];
        if (typeof externalKey.publicKey !== 'string'
            || !HEX.test(externalKey.publicKey)
            || externalKey.publicKey.length !== expectedLength
        ) {
            throw new Error(
                `The ${algorithm} key on the ticket is not a ${expectedLength}-character `
                + `compressed public key. Start the import again in the Dashboard and check the `
                + `public key you give it.`
            );
        }

        // The nodes rebuild the group public key from the parts they import and compare it with
        // the one they were handed. If the ticket describes a different key from the one this
        // package holds, the whole ceremony runs and then every node refuses - so it is refused
        // here instead, where the client can still pick the other file.
        //
        // The declared CHAIN CODE gets no such comparison, deliberately: nothing downstream
        // compares it either, it is simply the one the nodes will store, and on a migration the
        // client's declaration of it is the only statement of what it should be.
        const packagePublicKey = recoveryData.getCompressedPublicKey().toString('hex');
        if (externalKey.publicKey.toLowerCase() !== packagePublicKey.toLowerCase()) {
            throw new Error(
                `The ticket is for the ${algorithm} key ${externalKey.publicKey}, but this backup `
                + `data file holds the key ${packagePublicKey}. They are not the same key - `
                + `choose the backup file for the key you are migrating, or start the import `
                + `again with this key's public key.`
            );
        }

        return externalKey;
    }

    /**
     * Every seat the ticket names must import its own part: a node left out does not fail the
     * ceremony honestly, it takes part in it holding nothing, and the sharing that comes out is
     * not the key that went in. So a package that cannot cover the ticket is refused here,
     * before anything is sealed to anyone.
     *
     * @param {RecoveryDataEntity} recoveryData
     * @param {number[]} seats
     * @param {boolean} isRecovery
     * @param {number} oldThreshold
     * @private
     */
    _assertPackageCoversTheTicket(recoveryData, seats, isRecovery, oldThreshold) {
        const missing = seats.filter(index => recoveryData.getKeyPart(index) === null);
        if (recoveryData.getKeyParts().every(part => part.getIndex() === null)) {
            throw new Error(
                "The backup package holds no part for any seat in the ticket. A package whose "
                + "parts carry no player index - the shared/ERS format - cannot be used for a "
                + "key import, because a part's seat cannot be identified from its position."
            );
        }

        if (missing.length) {
            throw new Error(
                `The ticket asks for ${seats.length} parts and this backup package holds no part `
                + `for ${this._seatList(missing)}. Every seat in the ticket has to import its own `
                + `part, so check this is the backup of the vault being imported - an older `
                + `package, taken before the vault gained a player, will be short like this.`
            );
        }

        if (isRecovery && seats.length < oldThreshold) {
            throw new Error(
                `The ceremony needs ${oldThreshold} parts and the ticket asks for only `
                + `${seats.length}. Reset the import in the Dashboard and start it again.`
            );
        }
    }

    /**
     * Opens one part, turning a key that cannot open the package into a sentence about the two
     * files rather than the RSA library's own wording.
     *
     * @param {RecoveryDataEntity} recoveryData
     * @param {number} index
     * @param {string} rsaPrivateKey
     * @param {string} curve
     * @return {Buffer}
     * @private
     */
    _openKeyPart(recoveryData, index, rsaPrivateKey, curve) {
        try {
            return recoveryData
                .getKeyPart(index)
                .recoverKeyShare(rsaPrivateKey, curve)
                .toArrayLike(Buffer, 'be', envelope.POINT_BYTES_LENGTH);
        } catch (e) {
            throw new Error(
                `The part for seat #${index} could not be opened with this RSA private key. The `
                + `backup data file and the private key have to be the pair you made together.`
            );
        }
    }

    /**
     * @param {number[]} seats
     * @return {string}
     * @private
     */
    _seatList(seats) {
        return seats.map(seat => `seat #${seat}`).join(', ');
    }
}

module.exports = KeyImportService;
