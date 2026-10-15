'use strict';

const BN = require('bn.js');
const BaseEntity = require('./baseEntity');
const lagrange = require('../utils/lagrange');
const eciesUtils = require('../utils/ecies');
const {DOMAIN_PARAMS} = require('../enumerations/curve');
const PACKAGE = require('../enumerations/backupPackage');

/**
 * The file an embedded-wallet (WaaS) user keeps, as the server e-mails it:
 *
 *   { version, createdAt, walletId, recipientPublicKey, keys: [{keyId, algorithm}],
 *     shares: [ one sealed part per (keyId, index 0|1|2), plus the browser's mpc-identity ],
 *     chainCode: one sealed part }
 *
 * Every share is sealed toward Q, the P-256 public key the user's 24 words
 * derive. Nothing in the file opens without them.
 */
class BackupPackageEntity extends BaseEntity {

    /**
     * @return {string}
     */
    getWalletId() {
        return this.data['walletId'];
    }

    /**
     * @return {number|null}
     */
    getCreatedAt() {
        return this.data['createdAt'];
    }

    /**
     * @return {string} Q, uncompressed P-256, lowercase hex
     */
    getRecipientPublicKeyHex() {
        return this.data['recipientPublicKey'];
    }

    /**
     * @return {{keyId: string, algorithm: string}[]}
     */
    getKeys() {
        return this.data['keys'];
    }

    /**
     * @param {string} keyId
     * @return {Object<number, object>} the sealed shares of that key, by index
     */
    getSharesOf(keyId) {
        return this.data['shares'][keyId] || Object.create(null);
    }

    /**
     * @return {object|null}
     */
    getChainCodePart() {
        return this.data['chainCode'];
    }

    /**
     * @inheritDoc
     */
    _prepareData(data) {
        // Keyed by strings the file chose, so no prototype: a part labelled
        // "__proto__" must land nowhere, not on Object.prototype.
        const shares = Object.create(null);
        for (const part of data['shares']) {
            // The browser's transport identity moves no funds: not a share, skipped.
            if (part.keyId === PACKAGE.IDENTITY_KEY_ID) {
                continue;
            }

            shares[part.keyId] = shares[part.keyId] || Object.create(null);
            shares[part.keyId][part.index] = part;
        }

        return {
            walletId: String(data['walletId']),
            createdAt: typeof data['createdAt'] === 'number' ? data['createdAt'] : null,
            recipientPublicKey: data['recipientPublicKey'].toLowerCase(),
            keys: data['keys'].map(key => ({keyId: String(key.keyId), algorithm: String(key.algorithm)})),
            shares: shares,
            chainCode: data['chainCode'] || null,
        };
    }

    /**
     * @return {string[]}
     * @protected
     */
    _getRequiredAttributes() {
        return ['version', 'walletId', 'recipientPublicKey', 'keys', 'shares'];
    }

    /**
     * @inheritDoc
     */
    _validateAttributes(data) {
        BackupPackageEntity.assertVersion(data);
        super._validateAttributes(data);

        if (!eciesUtils.validRecipient(String(data['recipientPublicKey']).toLowerCase())) {
            throw new Error('The backup package names an invalid recovery public key.');
        }

        if (!Array.isArray(data['keys']) || data['keys'].length === 0) {
            throw new Error('The backup package lists no keys.');
        }

        for (const key of data['keys']) {
            if (!key || typeof key.keyId !== 'string' || !Object.prototype.hasOwnProperty.call(DOMAIN_PARAMS, key.algorithm)) {
                throw new Error(`The backup package lists a key of an unknown algorithm: "${key && key.algorithm}".`);
            }
        }

        if (!Array.isArray(data['shares']) || data['shares'].length === 0) {
            throw new Error('The backup package carries no sealed shares.');
        }
    }

    /**
     * The version is read before anything else: a file of another version may
     * have any shape, and is told apart by name rather than by what it lacks.
     *
     * @param {object} data
     * @return {void}
     */
    static assertVersion(data) {
        if (!data || data['version'] !== PACKAGE.VERSION) {
            throw new Error(
                `Unsupported backup package version "${data && data['version']}": this tool opens "${PACKAGE.VERSION}".`
            );
        }
    }

    /**
     * The words must derive the key the package was sealed toward. Checked
     * before any part is touched, so wrong words are told apart from a broken
     * file.
     *
     * @param {string} recoveryPublicKeyHex
     * @return {void}
     */
    assertSealedToward(recoveryPublicKeyHex) {
        if (recoveryPublicKeyHex !== this.getRecipientPublicKeyHex()) {
            throw new eciesUtils.RecoveryWordsError('These are not the recovery words of this backup file.');
        }
    }

    /**
     * Rebuild one key from its three shares: Lagrange interpolation at x = index + 1
     * over the curve's order, exactly as the key was split.
     *
     * @param {Buffer} d the recovery scalar
     * @param {{keyId: string, algorithm: string}} key
     * @return {string} the master private key, 32 bytes as hex
     */
    recoverPrivateKey(d, key) {
        const domainParams = DOMAIN_PARAMS[key.algorithm];
        const shares = this.getSharesOf(key.keyId);
        const indices = [];
        const values = [];

        for (const index of PACKAGE.SHARE_INDICES) {
            const part = shares[index];
            if (!part) {
                throw new Error(`The backup package is missing share ${index} of key ${key.keyId}.`);
            }

            if (part.algorithm !== key.algorithm) {
                throw new Error(`Share ${index} of key ${key.keyId} is labelled ${part.algorithm}, not ${key.algorithm}.`);
            }

            const point = eciesUtils.openPart(d, Buffer.from(this.getRecipientPublicKeyHex(), 'hex'), part);
            if (point.length !== PACKAGE.SHARE_BYTES) {
                point.fill(0);
                throw new Error(`Share ${index} of key ${key.keyId} is not a ${PACKAGE.SHARE_BYTES}-byte polynomial point.`);
            }

            indices.push(new BN(index + 1));
            values.push(new BN(point).mod(domainParams.n));
            point.fill(0);
        }

        return lagrange.reconstruct(indices, values, domainParams.n).toString('hex', 64);
    }

    /**
     * @param {Buffer} d the recovery scalar
     * @return {string} the master chain code, 32 bytes as hex
     */
    recoverChainCode(d) {
        const part = this.getChainCodePart();
        if (!part) {
            throw new Error('The backup package carries no master chain code.');
        }

        const expected = PACKAGE.CHAIN_CODE_LABEL;
        if (part.keyId !== expected.keyId || part.index !== expected.index || part.algorithm !== expected.algorithm) {
            throw new Error('The backup package carries a master chain code under the wrong label.');
        }

        const chainCode = eciesUtils.openPart(d, Buffer.from(this.getRecipientPublicKeyHex(), 'hex'), part);
        if (chainCode.length !== PACKAGE.SHARE_BYTES) {
            chainCode.fill(0);
            throw new Error(`The master chain code is not ${PACKAGE.SHARE_BYTES} bytes.`);
        }

        const hex = chainCode.toString('hex');
        chainCode.fill(0);

        return hex;
    }
}

module.exports = BackupPackageEntity;
