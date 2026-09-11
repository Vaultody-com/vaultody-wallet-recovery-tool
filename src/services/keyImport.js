'use strict';

const path = require('path');
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
     * Reads the input files, opens every key part the ticket asks for - for every algorithm the
     * ticket lists - and re-seals each one to the node that owns that seat, all inside this one
     * call, mirroring recoverWalletXPriv. What crosses the IPC boundary on the way back is the
     * sealed file's text: ciphertext addressed to the nodes, and no plaintext part at any point.
     *
     * ONE FILE COMES BACK, COVERING EVERY ALGORITHM. vaults-manager walks every algorithm on the
     * ticket and refuses an upload that is short one, so a per-algorithm file could never be
     * accepted on a vault holding both an ecdsa and an eddsa key.
     *
     * @param {object} event
     * @param {string} ticketPath
     * @param {string[]|string} dataPaths one VAULTODY backup data file per algorithm on the ticket
     * @param {string} rsaPath
     * @param {string} privateKeyType
     * @param {string|null} password
     * @return {Promise<{error: string}|{fileName: string, file: string, vaultId: string,
     *          kind: string, sealedPartCount: number,
     *          keys: {algorithm: string, keyId: string, declaredPublicKey: string|null,
     *          seats: number[]}[]}>}
     */
    async sealKeyParts(event, ticketPath, dataPaths, rsaPath, privateKeyType, password = null) {
        const ticketJson = await this.getJsonFromFile(ticketPath);
        if (!ticketJson) {
            return {error: "Key import ticket file is invalid"};
        }

        const ticketErrors = this.validator.validateKeyImportTicket(ticketJson);
        if (ticketErrors) {
            return {
                error: "That file is not a key import ticket: " + this.describeValidationErrors(ticketErrors)
                    + ". Download the ticket again from the VAULTODY Dashboard.",
            };
        }

        const backupPaths = Array.isArray(dataPaths) ? dataPaths : [dataPaths].filter(Boolean);
        if (backupPaths.length === 0) {
            return {error: "Choose your VAULTODY backup data file - one for each key on the ticket."};
        }

        const recoveryData = [];
        for (const backupPath of backupPaths) {
            const loaded = await this.loadRecoveryData(backupPath);
            if (loaded.error) {
                return loaded;
            }

            recoveryData.push(loaded.recoveryData);
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
                recoveryData,
                await this.fs.readFile(rsaPath),
                privateKeyType,
                password
            );
        } catch (e) {
            return {error: String(e && e.message ? e.message : e)};
        }

        return {
            // No algorithm in the name any more: one file carries every algorithm the ticket
            // listed, which is the only shape the Dashboard accepts.
            fileName: `key_import_${sealed.vaultId}.json`,
            // The upload the Dashboard expects: the CompleteKeyImport payload minus the
            // verification code, which the client types there rather than carrying in a file.
            file: JSON.stringify({
                vaultId: sealed.vaultId,
                kind: sealed.kind,
                sealedParts: sealed.sealedParts,
            }, null, 4),
            vaultId: sealed.vaultId,
            kind: sealed.kind,
            keys: sealed.keys,
            sealedPartCount: sealed.sealedParts.length,
        };
    }

    /**
     * Reads one backup data file and turns it into an entity, naming the FILE in every refusal -
     * with several of them on screen at once, "validation failed" no longer says which one to
     * replace.
     *
     * @param {string} backupPath
     * @return {Promise<{error: string}|{recoveryData: RecoveryDataEntity}>}
     */
    async loadRecoveryData(backupPath) {
        const name = path.basename(String(backupPath));
        const recoveryDataJson = await this.getJsonFromFile(backupPath);
        if (!recoveryDataJson) {
            return {error: `"${name}" could not be read as JSON, so it is not a backup data file.`};
        }

        if (this.validator.validateRecoveryData(recoveryDataJson)) {
            return {
                error: `"${name}" is not a VAULTODY backup data file. This tool seals from the `
                    + `.json your Dashboard produced when you backed the vault up - it must carry `
                    + `public_key, sharing_type, version, master_chain_code, master_chain_code_key `
                    + `and a key_parts entry per player. A key export from another custodian is `
                    + `not this format and cannot be sealed here.`,
            };
        }

        try {
            return {recoveryData: new RecoveryDataEntity(recoveryDataJson)};
        } catch (e) {
            return {error: `"${name}" could not be read as a backup data file: ${String(e && e.message ? e.message : e)}`};
        }
    }

    /**
     * Turns validate.js's nested result into one sentence. The constraint can only say that
     * the file is not a ticket, but it can at least say which field made it not one, instead
     * of leaving the client with "validation failed" and nothing to look at.
     *
     * @param {object} errors
     * @return {string}
     */
    describeValidationErrors(errors) {
        const messages = [];
        const collect = (node) => {
            if (typeof node === 'string') {
                messages.push(node);
            } else if (Array.isArray(node)) {
                node.forEach(collect);
            } else if (node !== null && typeof node === 'object') {
                Object.values(node).forEach(collect);
            }
        };

        collect(errors);

        return [...new Set(messages)].join('; ');
    }
}

module.exports = KeyImportService;
