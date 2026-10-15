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
 *     shares: [ one sealed part per (keyId, index 0|1|2), one chain code per key
 *               under {keyId, 0, "chain-code"}, plus the browser's mpc-identity ],
 *     chainCode / chainCodes: where an assembler keeps the chain-code parts apart }
 *
 * Every part is sealed toward Q, the P-256 public key the user's 24 words
 * derive. Nothing in the file opens without them. Chain-code parts are read
 * from wherever the file keeps them; a package from before the per-key label
 * carries one under `master-chain-code|0|-`, which then serves every key.
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
     * The chain code sealed for this key, or the package-wide one of an older
     * file, or null when the file carries neither.
     *
     * @param {string} keyId
     * @return {object|null}
     */
    getChainCodePartOf(keyId) {
        return this.data['chainCodes'][keyId] || this.data['legacyChainCode'] || null;
    }

    /**
     * @inheritDoc
     */
    _prepareData(data) {
        // Keyed by strings the file chose, so no prototype: a part labelled
        // "__proto__" must land nowhere, not on Object.prototype.
        const shares = Object.create(null);
        const chainCodes = Object.create(null);
        let legacyChainCode = null;

        for (const part of BackupPackageEntity.allParts(data)) {
            if (BackupPackageEntity.isChainCode(part)) {
                chainCodes[part.keyId] = part;
            } else if (BackupPackageEntity.isLegacyChainCode(part)) {
                legacyChainCode = part;
            } else if (part.keyId !== PACKAGE.IDENTITY_KEY_ID) {
                // The browser's transport identity moves no funds: not a share, skipped.
                shares[part.keyId] = shares[part.keyId] || Object.create(null);
                shares[part.keyId][part.index] = part;
            }
        }

        return {
            walletId: String(data['walletId']),
            createdAt: typeof data['createdAt'] === 'number' ? data['createdAt'] : null,
            recipientPublicKey: data['recipientPublicKey'].toLowerCase(),
            keys: data['keys'].map(key => ({keyId: String(key.keyId), algorithm: String(key.algorithm)})),
            shares: shares,
            chainCodes: chainCodes,
            legacyChainCode: legacyChainCode,
        };
    }

    /**
     * Every sealed part the file carries, wherever its assembler put it: the
     * `shares` list, a `chainCode` object, a `chainCodes` list.
     *
     * @param {object} data
     * @return {object[]}
     */
    static allParts(data) {
        const parts = [...data['shares']];
        if (data['chainCode'] && typeof data['chainCode'] === 'object') {
            parts.push(data['chainCode']);
        }
        if (Array.isArray(data['chainCodes'])) {
            parts.push(...data['chainCodes']);
        }

        return parts.filter(part => part && typeof part === 'object');
    }

    /**
     * @param {object} part
     * @return {boolean}
     */
    static isChainCode(part) {
        return part.index === PACKAGE.CHAIN_CODE_INDEX && part.algorithm === PACKAGE.CHAIN_CODE_ALGORITHM;
    }

    /**
     * @param {object} part
     * @return {boolean}
     */
    static isLegacyChainCode(part) {
        const legacy = PACKAGE.LEGACY_CHAIN_CODE_LABEL;

        return part.keyId === legacy.keyId && part.index === legacy.index && part.algorithm === legacy.algorithm;
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
     * The chain code of one key: its own sealed part, or the package-wide one
     * of an older file. Its label is bound into the ciphertext, so the ed25519
     * key's chain code relabelled as the secp256k1 key's does not open.
     *
     * @param {Buffer} d the recovery scalar
     * @param {{keyId: string, algorithm: string}} key
     * @return {string} the master chain code, 32 bytes as hex
     */
    recoverChainCode(d, key) {
        const part = this.getChainCodePartOf(key.keyId);
        if (!part) {
            throw new Error(`The backup package carries no chain code for key ${key.keyId}.`);
        }

        const chainCode = eciesUtils.openPart(d, Buffer.from(this.getRecipientPublicKeyHex(), 'hex'), part);
        if (chainCode.length !== PACKAGE.SHARE_BYTES) {
            chainCode.fill(0);
            throw new Error(`The chain code of key ${key.keyId} is not ${PACKAGE.SHARE_BYTES} bytes.`);
        }

        const hex = chainCode.toString('hex');
        chainCode.fill(0);

        return hex;
    }
}

module.exports = BackupPackageEntity;
