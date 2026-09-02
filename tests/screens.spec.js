'use strict';

const {test, expect} = require('@playwright/test');
const {launchApp, navigateTo, SCREENS} = require('./helpers');

let electronApp, window, errors;

test.beforeEach(async () => {
    ({electronApp, window, errors} = await launchApp());
});

test.afterEach(async () => {
    await electronApp?.close();
});

test('every screen renders its heading, the rail and the offline indicator', async () => {
    for (const screen of Object.values(SCREENS)) {
        await navigateTo(window, screen.nav, screen.heading);

        await expect(window.locator('#offline-indicator')).toContainText('offline');
        await expect(window.locator(`#${screen.nav}.nav-item.active`)).toHaveCount(1);
        await expect(window.locator('.nav-item')).toHaveCount(4);
        await expect(window.locator('#rail-source')).toBeVisible();
    }

    expect(errors).toEqual([]);
});

test('the VAULTODY-provided recovery screen renders', async () => {
    // Nothing in the UI navigates here — it never has — so drive the screen
    // channel the main process already registers.
    await electronApp.evaluate(({ipcMain}) => ipcMain.emit('screen:recover-vaultody-provided'));
    await window.waitForSelector('.page-title:has-text("RSA key provided by VAULTODY")');

    await expect(window.locator('#offline-indicator')).toContainText('offline');
    await expect(window.locator('#recoveryDataFileButton')).toBeVisible();
    await expect(window.locator('#rsaFileButton')).toBeVisible();
    await expect(window.locator('#password')).toHaveAttribute('type', 'password');

    expect(errors).toEqual([]);
});

test('home surfaces the open-source provenance instead of a wall of text', async () => {
    await expect(window.locator('.prov')).toHaveCount(4);
    await expect(window.locator('#home-provenance')).toContainText('MIT License');
    await expect(window.locator('#home-provenance')).toContainText('No telemetry, no network');
    await expect(window.locator('.launch .tool')).toHaveCount(3);

    expect(errors).toEqual([]);
});
