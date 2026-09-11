const {app, BrowserWindow, ipcMain} = require('electron');

const {IS_MAC} = require('./config');
const Base = require('./base');
const RecoverService = require('./services/recover');
const KeyImportService = require('./services/keyImport');
const UtilityService = require('./services/utility');
const ScreenService = require('./services/screen');
const FileService = require('./services/file');

app.on('window-all-closed', () => {
    if (!IS_MAC) {
        app.quit();
    }
});

app.whenReady().then(() => {
    const base = new Base();

    const mainWindow = base.createWindow();
    base.createMenu(mainWindow);

    const recoverService = new RecoverService();
    const keyImportService = new KeyImportService();
    const utilityService = new UtilityService();
    const screenService = new ScreenService(mainWindow);
    const fileService = new FileService(mainWindow);

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) base.createWindow()
    });

    ipcMain.handle('recover:recover-xpriv', recoverService.recoverWalletXPriv.bind(recoverService));

    ipcMain.handle('key-import:seal-parts', keyImportService.sealKeyParts.bind(keyImportService));
    ipcMain.handle('key-import:pinned-node-keys', keyImportService.pinnedNodeKeys.bind(keyImportService));

    ipcMain.handle("utility:generate-rsa-key", utilityService.generateRsaKey.bind(utilityService));
    ipcMain.handle("utility:generate-password", utilityService.generatePassword.bind(utilityService));
    ipcMain.handle('utility:open-link', utilityService.openLinkInBrowser.bind(utilityService));
    ipcMain.handle('utility:clipboard-copy', utilityService.clipboardCopy.bind(utilityService));

    ipcMain.on('screen:generate-password', screenService.renderPasswordGeneratorView.bind(screenService));
    ipcMain.on('screen:rsa-key-generator', screenService.renderRsaKeyGeneratorView.bind(screenService));
    ipcMain.on('screen:recover-self-provided', screenService.renderRecoverSelfProvidedView.bind(screenService));
    ipcMain.on('screen:key-import', screenService.renderKeyImportView.bind(screenService));
    ipcMain.on('screen:home', screenService.renderHomeView.bind(screenService));

    ipcMain.handle('file:recovery-data', fileService.recoveryData.bind(fileService));
    ipcMain.handle('file:rsa-key', fileService.recoverRsaKey.bind(fileService));
    ipcMain.handle('file:key-import-ticket', fileService.keyImportTicket.bind(fileService));
});