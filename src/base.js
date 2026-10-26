'use strict'

const {BrowserWindow, app, Menu} = require('electron');
const {
    INDEX_HTML_FILE_PATH,
    MAIN_WINDOW_OPTIONS,
    ABOUT_WINDOW_OPTIONS,
    ABOUT_HTML_FILE_PATH,
    IS_MAC,
} = require('./config');
const {buildMenuTemplate} = require('./menu');

class Base {

    /**
     * @return {Electron.CrossProcessExports.BrowserWindow}
     */
    createWindow() {
        const mainWindow = new BrowserWindow(MAIN_WINDOW_OPTIONS);
        mainWindow.loadFile(INDEX_HTML_FILE_PATH);
        mainWindow.on('closed', function () {
            app.quit();
        });

        if (IS_MAC) {
            mainWindow.webContents.on('context-menu', (e, props) => {
                const {selectionText, isEditable} = props;
                if (isEditable || selectionText.length > 0) {
                    const menuTemplate = [];
                    if (isEditable) {
                        menuTemplate.push({role: 'undo'});
                        menuTemplate.push({role: 'redo'});
                        menuTemplate.push({type: 'separator'});
                        menuTemplate.push({role: 'cut'});
                    }
                    menuTemplate.push({role: 'copy'});
                    if (isEditable) {
                        menuTemplate.push({role: 'paste'});
                        menuTemplate.push({role: 'delete'});
                        menuTemplate.push({type: 'separator'});
                        menuTemplate.push({role: 'selectAll'});
                    }
                    Menu.buildFromTemplate(menuTemplate).popup(mainWindow);
                }
            });
        }

        return mainWindow;
    }

    createMenu() {
        const template = buildMenuTemplate({
            isMac: IS_MAC,
            isPackaged: app.isPackaged,
            appName: app.getName(),
        });

        Menu.setApplicationMenu(Menu.buildFromTemplate(template));
    }

    createAboutWindow() {
        let aboutWindow = new BrowserWindow(ABOUT_WINDOW_OPTIONS);
        aboutWindow.loadFile(ABOUT_HTML_FILE_PATH);
        aboutWindow.on('close', () => {
            aboutWindow = null;
        });
    }
}

module.exports = Base;