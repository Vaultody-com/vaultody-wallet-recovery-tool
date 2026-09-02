'use strict';

const path = require('path');
const {_electron: electron} = require('@playwright/test');

const APP_ROOT = path.join(__dirname, '..');
const EXAMPLE_DATA_DIR = path.join(APP_ROOT, 'examples', 'data');

const SCREENS = {
    home: {nav: 'home', heading: 'Recover your vault without depending on anyone.'},
    password: {nav: 'generate-password', heading: 'Generate a random password'},
    rsa: {nav: 'rsa-key-pairs', heading: 'Generate an RSA key pair'},
    recover: {nav: 'recovery', heading: 'Recover your vault'},
};

/**
 * Launches the packaged renderer against a real Electron main process and
 * collects everything the renderer got wrong: uncaught exceptions and Content
 * Security Policy violations.
 *
 * @return {Promise<{electronApp: object, window: object, errors: string[]}>}
 */
async function launchApp() {
    const electronApp = await electron.launch({args: [APP_ROOT], cwd: APP_ROOT});
    const window = await electronApp.firstWindow();
    const errors = [];

    window.on('pageerror', error => errors.push(`pageerror: ${error.message}`));
    window.on('console', message => {
        if (message.type() === 'error' && message.text().includes('Content Security Policy')) {
            errors.push(`csp: ${message.text()}`);
        }
    });

    await window.waitForSelector('#offline-indicator');

    return {electronApp, window, errors};
}

/**
 * Replaces the native open-file dialog so the renderer's file flows can be
 * driven from a test. The main process reads the path from a global that
 * `chooseFile` sets before each click.
 *
 * @param {object} electronApp
 */
async function stubFileDialog(electronApp) {
    await electronApp.evaluate(({dialog}) => {
        dialog.showOpenDialog = async () => ({
            canceled: !globalThis.__testFilePath,
            filePaths: globalThis.__testFilePath ? [globalThis.__testFilePath] : [],
        });
    });
}

/**
 * @param {object} electronApp
 * @param {object} window
 * @param {string} buttonSelector
 * @param {string} fileName
 */
async function chooseFile(electronApp, window, buttonSelector, fileName) {
    await electronApp.evaluate((_electron, filePath) => {
        globalThis.__testFilePath = filePath;
    }, path.join(EXAMPLE_DATA_DIR, fileName));

    await window.click(buttonSelector);
}

/**
 * Navigates by clicking the rail, i.e. the way a user gets between screens.
 *
 * @param {object} window
 * @param {string} navId
 * @param {string} heading
 */
async function navigateTo(window, navId, heading) {
    await window.click(`#${navId}`);
    // :text-is is an exact match — :has-text would match Home's title, which
    // contains the recovery screen's title as a prefix, and let the wait pass
    // before the navigation actually happened.
    await window.waitForSelector(`.page-title:text-is(${JSON.stringify(heading)})`);
    await window.waitForSelector('#offline-indicator');
}

module.exports = {
    APP_ROOT,
    EXAMPLE_DATA_DIR,
    SCREENS,
    launchApp,
    stubFileDialog,
    chooseFile,
    navigateTo,
};
