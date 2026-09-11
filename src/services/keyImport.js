'use strict';

const {promises: fs} = require('fs');
const RecoveryDataEntity = require('../lib/entities/recoveryDataEntity');
const KeyImportToolService = require('../lib/services/keyImportService');
const BaseService = require('./base');
const privateKeyTypeEnum = require('../lib/enumerations/privateKeyType');

class KeyImportService extends BaseService {
    constructor() {
        super();
        this.keyImportToolService = new KeyImportToolService();
    }

    /**
     * Reads the three input files, opens every key part the ticket asks for and re-seals it to
     * the node that owns that seat - all inside this one call, mirroring recoverWalletXPriv.
     * What crosses the IPC boundary on the way back is the sealed file's text: ciphertext
     * addressed to the nodes, and no plaintext part at any point.
     *
     * @param {object} event
     * @param {string} ticketPath
     * @param {string} dataPath
     * @param {string} rsaPath
     * @param {string} privateKeyType
     * @param {string|null} password
     * @return {Promise<{error: string}|{fileName: string, file: string, vaultId: string,
     *          kind: string, algorithm: string, keyId: string, sealedSeats: number[],
     *          seatsWithoutAPart: number[]}>}
     */
    async sealKeyParts(event, ticketPath, dataPath, rsaPath, privateKeyType, password = null) {
        const ticketJson = await this.getJsonFromFile(ticketPath);
        if (!ticketJson) {
            return {error: "Key import ticket file is invalid"};
        }

        if (this.validator.validateKeyImportTicket(ticketJson)) {
            return {error: "Key import ticket file validation failed"};
        }

        const recoveryDataJson = await this.getJsonFromFile(dataPath);
        if (!recoveryDataJson) {
            return {error: "Recovery data input file is invalid"};
        }

        if (this.validator.validateRecoveryData(recoveryDataJson)) {
            return {error: "Recovery data input file validation failed"};
        }

        const privateKeyDataJson = privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED)
            ? await this.getJsonFromFile(rsaPath)
            : await fs.readFile(rsaPath).catch(_ => null);
        if (!privateKeyDataJson) {
            return {error: "Private RSA key input file is invalid"};
        }

        if (this.validator.validatePrivateKey(privateKeyDataJson, privateKeyType)) {
            return {error: "Private RSA key input file validation failed"};
        }

        if (privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED) && !this.validator.validatePassword(password)) {
            return {error: "Password must not be empty and have at least one upper case letter, one number and one special symbol"};
        }

        let sealed;
        try {
            sealed = this.keyImportToolService.sealKeyParts(
                ticketJson,
                new RecoveryDataEntity(recoveryDataJson),
                await this.fs.readFile(rsaPath),
                privateKeyType,
                password
            );
        } catch (e) {
            return {error: String(e && e.message ? e.message : e)};
        }

        return {
            fileName: `key_import_${sealed.vaultId}_${sealed.algorithm}.json`,
            // The upload the Dashboard expects: the CompleteKeyImport payload minus the
            // verification code, which the client types there rather than carrying in a file.
            file: JSON.stringify({
                vaultId: sealed.vaultId,
                kind: sealed.kind,
                sealedParts: sealed.sealedParts,
            }, null, 4),
            vaultId: sealed.vaultId,
            kind: sealed.kind,
            algorithm: sealed.algorithm,
            keyId: sealed.keyId,
            sealedSeats: sealed.sealedSeats,
            seatsWithoutAPart: sealed.seatsWithoutAPart,
        };
    }
}

module.exports = KeyImportService;
