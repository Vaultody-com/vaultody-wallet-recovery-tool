'use strict';

const {dialog} = require('electron');
const BaseService = require('./base');
const privateKeyTypeEnum = require("../lib/enumerations/privateKeyType");
const {promises: fs} = require('fs');

class FileService extends BaseService {
    constructor(mainWindow) {
        super();
        this.mainWindow = mainWindow;
    }

    /**
     * The backup data picker. A key import covers every algorithm the vault holds in one run,
     * so that screen asks for several files at once; the recovery screen rebuilds one key and
     * asks for a single one.
     *
     * Whichever it is, EVERY chosen file is validated, and the paths that failed come back named
     * so the caller can say which one to replace rather than just that something was wrong.
     *
     * @param {object} event
     * @param {boolean} multiple
     * @return {Promise<Electron.OpenDialogReturnValue & {invalidPaths: string[]}>}
     */
    async recoveryData(event, multiple = false) {
        const fileData = await dialog.showOpenDialog({
            properties: multiple ? ['openFile', 'multiSelections'] : ['openFile'],
            filters: [
                {name: 'JSON', extensions: ['json']},
            ]
        });

        const invalidPaths = [];
        if (!fileData.canceled) {
            for (const filePath of fileData.filePaths) {
                const recoveryDataJson = await this.getJsonFromFile(filePath);
                if (!recoveryDataJson || this.validator.validateRecoveryData(recoveryDataJson)) {
                    invalidPaths.push(filePath);
                }
            }

            this.mainWindow.webContents.send("status:recovery-data", invalidPaths.length === 0);
        }

        return {...fileData, invalidPaths: invalidPaths};
    }

    /**
     * @return {Promise<Electron.OpenDialogReturnValue>}
     */
    async keyImportTicket() {
        const fileData = await dialog.showOpenDialog({
            properties: ['openFile'],
            filters: [
                {name: 'JSON', extensions: ['json']},
            ]
        });

        let status = true;
        if (!fileData.canceled) {
            const ticketJson = await this.getJsonFromFile(fileData.filePaths[0]);
            if (!ticketJson) {
                status = false;
            } else {
                const validationResponse = this.validator.validateKeyImportTicket(ticketJson);
                if (validationResponse) {
                    status = false;
                }
            }

            this.mainWindow.webContents.send("status:key-import-ticket", status);
        }

        return fileData;
    }

    /**
     * @param {object} event
     * @param {string} privateKeyType
     * @return {Promise<Electron.OpenDialogReturnValue>}
     */
    async recoverRsaKey(event, privateKeyType) {
        const fileData = await dialog.showOpenDialog({
            properties: ['openFile']
        });

        let status = true;
        if (!fileData.canceled) {
            const privateKey = privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED)
                ? await this.getJsonFromFile(fileData.filePaths[0])
                : await fs.readFile(fileData.filePaths[0]).catch(_ => null);

            if (!privateKey) {
                status = false;
            } else {
                const validationResponse = this.validator.validatePrivateKey(privateKey, privateKeyType);
                if (validationResponse) {
                    status = false;
                }
            }

            this.mainWindow.webContents.send("status:rsa-key", status);
        }

        return fileData;
    }
}

module.exports = FileService;