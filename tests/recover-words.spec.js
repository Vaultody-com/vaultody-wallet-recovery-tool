'use strict';

const fs = require('fs');
const path = require('path');
const {test, expect} = require('@playwright/test');
const {launchApp, navigateTo, stubFileDialog, chooseFile, SCREENS, EXAMPLE_DATA_DIR} = require('./helpers');
const example = require('../examples/make-backup-package');

// What examples/data/backup_package_ecies_p256_v1.json recovers to — see
// examples/recover-from-words.js and tests/backup-package.spec.js.
const EXPECTED_SECP_XPRIV =
    'xprv9s21ZrQH143K3yfVznf9aKiXatifXY2AsSinG1S5Ab6BRHco2rZenrL1nJMs1DUp9Zxz3ryggvN95n1jvTAN4ij4DGy6F4UmmNaxPoAmrAz';
const EXPECTED_SECP_XPUB =
    'xpub661MyMwAqRbcGTjy6pC9wTfG8vZ9vzk2EfeP4PqgivdAJ5wwaPsuLeeVdcvfYV7U5gTj41soapMdD4c2AufPZAcjJPABsNKMeBSoKizqQAx';

let electronApp, window, errors;

test.beforeEach(async () => {
    ({electronApp, window, errors} = await launchApp());
    await stubFileDialog(electronApp);
    await navigateTo(window, SCREENS.words.nav, SCREENS.words.heading);
});

test.afterEach(async () => {
    await electronApp?.close();
});

test('the words are masked on load and revealed only when asked', async () => {
    const words = window.locator('#recoveryWords');

    await expect(words).toHaveClass(/masked-text/);
    expect(await words.evaluate(el => getComputedStyle(el).webkitTextSecurity)).toBe('disc');

    await window.click('#recoveryWords-reveal');
    await expect(words).not.toHaveClass(/masked-text/);
    expect(await words.evaluate(el => getComputedStyle(el).webkitTextSecurity)).toBe('none');

    await window.click('#recoveryWords-reveal');
    await expect(words).toHaveClass(/masked-text/);

    expect(errors).toEqual([]);
});

test('a chosen file reports whether it is a backup package', async () => {
    await chooseFile(electronApp, window, '#backupPackageFileButton', 'backup_package_ecies_p256_v1.json');
    await expect(window.locator('#backupPackageFilePicker')).toHaveClass(/loaded/);
    await expect(window.locator('#backupPackageFileStatus')).toContainText('accepted');

    // The dashboard's RSA recovery data is valid JSON but not this format.
    await chooseFile(electronApp, window, '#backupPackageFileButton', 'recovery_data_ecdsa.json');
    await expect(window.locator('#backupPackageFilePicker')).toHaveClass(/invalid/);
    await expect(window.locator('#backupPackageFileStatus')).toContainText('rejected');

    expect(errors).toEqual([]);
});

test('the words and the file rebuild both master keys, masked by default', async () => {
    await chooseFile(electronApp, window, '#backupPackageFileButton', 'backup_package_ecies_p256_v1.json');
    await expect(window.locator('#backupPackageFilePicker')).toHaveClass(/loaded/);

    await window.fill('#recoveryWords', fs.readFileSync(path.join(EXAMPLE_DATA_DIR, 'recovery_words.txt'), 'utf8'));
    await window.click('#recoverWordsButton');

    await expect(window.locator('.result-card.safe')).toBeVisible({timeout: 30_000});
    await expect(window.locator('#recoveryWalletId')).toHaveText('example-vault-0001');

    // One masked xPriv per key, nothing readable until revealed.
    const secp = window.locator('#recoveryResult-0');
    await expect(secp).toHaveClass(/masked/);
    expect(await secp.textContent()).toMatch(/^•+$/);
    await expect(window.locator('#recoveryResult-1')).toHaveClass(/masked/);

    // The public half is what a recovery is checked against, so it is in the clear.
    await expect(window.locator('#recoveryPublic-0')).toHaveText(EXPECTED_SECP_XPUB);

    await window.click('#reveal-xpriv-0');
    await expect(secp).not.toHaveClass(/masked/);
    expect(await secp.textContent()).toBe(EXPECTED_SECP_XPRIV);

    expect(errors).toEqual([]);
});

test('wrong words fail with a readable message and no key', async () => {
    await chooseFile(electronApp, window, '#backupPackageFileButton', 'backup_package_ecies_p256_v1.json');

    const other = example.WORDS.split(' ');
    [other[0], other[2]] = [other[2], other[0]];
    await window.fill('#recoveryWords', other.join(' '));
    await window.click('#recoverWordsButton');

    await expect(window.locator('.result-card')).toBeVisible({timeout: 30_000});
    await expect(window.locator('.result-card.safe')).toHaveCount(0);
    await expect(window.locator('#recoveryResult')).toContainText('not 24 valid recovery words');
    await expect(window.locator('[id^=recoveryResult-]')).toHaveCount(0);

    expect(errors).toEqual([]);
});

test('without a file the words go nowhere', async () => {
    await window.fill('#recoveryWords', example.WORDS);
    await window.click('#recoverWordsButton');

    await expect(window.locator('#recoveryResult')).toContainText('Choose the backup package file');

    expect(errors).toEqual([]);
});
