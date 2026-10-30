'use strict';

const RecoveryDataEntity = require('../lib/entities/recoveryDataEntity');
const BaseService = require('./base');
const privateKeyTypeEnum = require("../lib/enumerations/privateKeyType");
const {promises: fs} = require("fs");

class RecoverService extends BaseService {
    constructor() {
        super();
    }

    /**
     * @param {object} event
     * @param {string} dataPath
     * @param {string} rsaPath
     * @param {string} privateKeyType
     * @param {string|null} password
     * @param {string|null} cosignerSharePath for a server co-signer vault, the client-provided share
     *     file (one part, index 2) exported from the client's own node. Merged with the Vaultody
     *     backup (its two shares) so all three parts are present. Null/empty for a mobile co-signer
     *     vault, whose backup already carries every part.
     * @return {Promise<string|null>}
     */
    async recoverWalletXPriv(event, dataPath, rsaPath, privateKeyType, password = null, cosignerSharePath = null) {
        const recoveryDataJson = await this.getJsonFromFile(dataPath);
        if (!recoveryDataJson) {
            return "Recovery data input file is invalid";
        }

        if (cosignerSharePath) {
            const mergeError = await this._mergeCosignerShare(recoveryDataJson, cosignerSharePath);
            if (mergeError) {
                return mergeError;
            }
        }

        const recoveryDataValidationResult = this.validator.validateRecoveryData(recoveryDataJson);
        if (recoveryDataValidationResult) {
            return "Recovery data input file validation failed";
        }

        const privateKeyDataJson = privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED)
            ? await this.getJsonFromFile(rsaPath)
            : await fs.readFile(rsaPath).catch(_ => null);
        if (!privateKeyDataJson) {
            return "Private RSA key input file is invalid";
        }

        const rsaValidationResult = this.validator.validatePrivateKey(privateKeyDataJson, privateKeyType);
        if (rsaValidationResult) {
            return "Private RSA key input file validation failed";
        }

        if (privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED) && !this.validator.validatePassword(password)) {
            return "Password must not be empty and have at least one upper case letter, one number and one special symbol";
        }

        const recoveryDataEntity = new RecoveryDataEntity(recoveryDataJson);
        try {
            return this.recoveryToolService.recoverXpriv(recoveryDataEntity, await this.fs.readFile(rsaPath), privateKeyType, password);
        } catch (e) {
            return e;
        }
    }

    /**
     * Merges the client-provided co-signer share (one part) into the Vaultody backup's key_parts, so
     * recovery has all three parts for a server co-signer vault. Mutates recoveryDataJson in place.
     * Returns an error string on a mismatch, or null on success. The part is encrypted to the same
     * RSA key as the Vaultody parts, so the one RSA private key decrypts all three downstream.
     *
     * @param {object} recoveryDataJson the Vaultody backup JSON (key_parts, public_key, ...)
     * @param {string} cosignerSharePath path to the client's share file ({data, index, public_key})
     * @return {Promise<string|null>}
     */
    async _mergeCosignerShare(recoveryDataJson, cosignerSharePath) {
        const shareJson = await this.getJsonFromFile(cosignerSharePath);
        if (!shareJson) {
            return "Co-signer share file is invalid";
        }

        if (typeof shareJson.data !== "string" || !Number.isInteger(shareJson.index)) {
            return "Co-signer share file is missing its key part";
        }

        const sharePublicKey = shareJson.publicKey || shareJson.public_key;
        if (typeof sharePublicKey !== "string" || !sharePublicKey) {
            return "Co-signer share file is missing its public key";
        }
        if (!this._publicKeysMatch(sharePublicKey, recoveryDataJson.public_key)) {
            return "Co-signer share does not match this backup (different vault)";
        }

        if (!Array.isArray(recoveryDataJson.key_parts)) {
            return "Backup file has no key parts to merge into";
        }

        if (recoveryDataJson.key_parts.some(part => part.index === shareJson.index)) {
            return "Co-signer share is already present in the backup file";
        }

        recoveryDataJson.key_parts.push({ data: shareJson.data, index: shareJson.index });

        return null;
    }

    /**
     * True when the co-signer share's public key is the same key as the Vaultody backup's, across the
     * two encodings in play: the client's node returns the raw compressed/edwards public key, while
     * the Vaultody part stores the same key wrapped in an SPKI (DER) header. The raw key is a
     * contiguous byte-subsequence of the SPKI, so decode both (base64) and test for containment; an
     * exact string match (already-normalised files) short-circuits first.
     *
     * @param {string} sharePublicKey the co-signer share's public key (raw, base64)
     * @param {string} backupPublicKey the Vaultody backup's public key (SPKI, base64)
     * @return {boolean}
     */
    _publicKeysMatch(sharePublicKey, backupPublicKey) {
        if (typeof backupPublicKey !== "string" || !backupPublicKey) {
            return false;
        }
        if (sharePublicKey === backupPublicKey) {
            return true;
        }
        try {
            const raw = Buffer.from(sharePublicKey, "base64");
            const spki = Buffer.from(backupPublicKey, "base64");

            return raw.length > 0 && spki.includes(raw);
        } catch (_) {
            return false;
        }
    }
}

module.exports = RecoverService;
