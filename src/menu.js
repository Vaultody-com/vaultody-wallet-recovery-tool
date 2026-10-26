'use strict'

const {MAIN_MENU_OPTIONS, MAIN_MENU_OPTIONS_DEV} = require('./config');

/**
 * Builds the application menu template.
 *
 * The Developer Tools submenu (Reload, Toggle Developer Tools) is only part of
 * the menu when the app runs unpackaged (`npm start`). A packaged release never
 * gets it: the tool reveals recovered keys on screen, and DevTools would hand
 * the renderer, the DOM and the console to anyone at the machine.
 *
 * @param {object} options
 * @param {boolean} options.isMac Whether the app runs on macOS.
 * @param {boolean} options.isPackaged `app.isPackaged` of the running app.
 * @param {string} options.appName Shown as the first menu on macOS.
 * @return {object[]} A fresh template array for `Menu.buildFromTemplate`.
 */
function buildMenuTemplate({isMac, isPackaged, appName}) {
    const template = [...MAIN_MENU_OPTIONS];

    if (isMac) {
        template.unshift({label: appName});
    }

    if (!isPackaged) {
        template.push(MAIN_MENU_OPTIONS_DEV);
    }

    return template;
}

module.exports = {
    buildMenuTemplate,
};
