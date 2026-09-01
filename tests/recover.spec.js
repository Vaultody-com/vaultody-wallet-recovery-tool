'use strict';

const {test, expect} = require('@playwright/test');
const {launchApp, navigateTo, stubFileDialog, chooseFile, SCREENS} = require('./helpers');

// The xPriv the sample data in examples/data recovers to — see examples/index.js.
const EXPECTED_ECDSA_XPRIV =
    'xprv9s21ZrQH143K24jyDYVEDbpcreer9Bu9REH8Xf48P5W2rF4jcBqgqFqPpxDF1ZJwoYsm6QTvTbn75mRbPTtq87hpD8YtG6A2MaJUmMP2Enw';

let electronApp, window, errors;

test.beforeEach(async () => {
    ({electronApp, window, errors} = await launchApp());
    await stubFileDialog(electronApp);
    await navigateTo(window, SCREENS.recoverSelf.nav, SCREENS.recoverSelf.heading);
});

test.afterEach(async () => {
    await electronApp.close();
});

test('the private key type toggle swaps the password field', async () => {
    // SJCL encrypted keys are password protected, so the field is there.
    await expect(window.locator('#password')).toHaveAttribute('type', 'password');
    await expect(window.locator('#rsaFileButton')).toBeVisible();

    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    // A raw PEM key is not encrypted — no password field at all.
    await expect(window.locator('#password')).toHaveCount(0);
    await expect(window.locator('#rsaFileButton')).toBeVisible();

    await window.selectOption('#privateKeySelect', 'sjclEncryptedPrivateKey');
    await expect(window.locator('#password')).toHaveAttribute('type', 'password');

    expect(errors).toEqual([]);
});

test('a chosen file reports whether it was accepted', async () => {
    await chooseFile(electronApp, window, '#recoveryDataFileButton', 'recovery_data_ecdsa.json');
    await expect(window.locator('#recoveryDataFilePicker')).toHaveClass(/loaded/);
    await expect(window.locator('#recoveryDataFileStatus')).toContainText('accepted');

    // A public key is a valid file but not valid recovery data.
    await chooseFile(electronApp, window, '#recoveryDataFileButton', 'public_key.txt');
    await expect(window.locator('#recoveryDataFilePicker')).toHaveClass(/invalid/);
    await expect(window.locator('#recoveryDataFileStatus')).toContainText('rejected');

    expect(errors).toEqual([]);
});

test('the recovery flow still produces the expected xPriv, masked by default', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFile(electronApp, window, '#recoveryDataFileButton', 'recovery_data_ecdsa.json');
    await expect(window.locator('#recoveryDataFilePicker')).toHaveClass(/loaded/);

    await chooseFile(electronApp, window, '#rsaFileButton', 'private_key.txt');
    await expect(window.locator('#rsaFilePicker')).toHaveClass(/loaded/);

    await window.click('#recoverButton');

    const result = window.locator('#recoveryResult');
    await expect(window.locator('.result-card.safe')).toBeVisible({timeout: 30_000});

    // The recovered master key must not be readable until it is asked for.
    await expect(result).toHaveClass(/masked/);
    expect(await result.textContent()).toMatch(/^•+$/);

    await window.click('#reveal-xpriv');
    await expect(result).not.toHaveClass(/masked/);
    expect(await result.textContent()).toBe(EXPECTED_ECDSA_XPRIV);

    expect(errors).toEqual([]);
});

test('a rejected key file fails with a readable message and no xPriv', async () => {
    // The SJCL flow is selected, so a raw PEM key is the wrong shape.
    await chooseFile(electronApp, window, '#recoveryDataFileButton', 'recovery_data_ecdsa.json');
    await chooseFile(electronApp, window, '#rsaFileButton', 'private_key.txt');
    await expect(window.locator('#rsaFilePicker')).toHaveClass(/invalid/);

    await window.fill('#password', 'Wr0ngPassword!');
    await window.click('#recoverButton');

    await expect(window.locator('.result-card')).toBeVisible({timeout: 30_000});
    await expect(window.locator('.result-card.safe')).toHaveCount(0);
    await expect(window.locator('#recoveryResult')).toContainText('Private RSA key input file is invalid');

    expect(errors).toEqual([]);
});
