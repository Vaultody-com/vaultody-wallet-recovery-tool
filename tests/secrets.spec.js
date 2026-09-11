'use strict';

const {test, expect} = require('@playwright/test');
const {launchApp, navigateTo, SCREENS} = require('./helpers');

const VALID_RSA_PASSWORD = 'Passw0rd!x';

let electronApp, window, errors;

test.beforeEach(async () => {
    ({electronApp, window, errors} = await launchApp());
});

test.afterEach(async () => {
    await electronApp?.close();
});

test('no screen renders a secret input in clear text on load', async () => {
    for (const screen of Object.values(SCREENS)) {
        await navigateTo(window, screen.nav, screen.heading);

        const types = await window.locator('input.input').evaluateAll(
            inputs => inputs.map(input => input.type)
        );

        expect(types.every(type => type === 'password'), `clear-text input on ${screen.nav}`).toBe(true);
    }

    expect(errors).toEqual([]);
});

test('the generated password is masked until revealed', async () => {
    await navigateTo(window, SCREENS.password.nav, SCREENS.password.heading);

    const input = window.locator('#generate-new-password-input');
    await expect(input).toHaveAttribute('type', 'password');

    // Step 1 only generates; a password of your own is typed in step 2, so the
    // copy on this screen must not promise an editable field.
    await expect(input).toHaveAttribute('readonly', '');

    await window.click('#generate-new-password-button');
    await expect(input).not.toHaveValue('');
    await expect(input).toHaveAttribute('type', 'password');

    await window.click('#reveal-password');
    await expect(input).toHaveAttribute('type', 'text');

    await window.click('#reveal-password');
    await expect(input).toHaveAttribute('type', 'password');

    expect(errors).toEqual([]);
});

test('the generated RSA private key is not in the DOM until revealed', async () => {
    await navigateTo(window, SCREENS.rsa.nav, SCREENS.rsa.heading);

    await window.fill('#password', VALID_RSA_PASSWORD);
    await window.click('#generate-button');

    const publicKey = window.locator('#generated-rsa-public-key-result');
    const privateKey = window.locator('#generated-rsa-private-key-result');

    await expect(publicKey).toContainText('BEGIN RSA PUBLIC KEY', {timeout: 30_000});

    // The public half is safe to show; the private half must not be readable.
    await expect(privateKey).toHaveClass(/masked/);
    expect(await privateKey.textContent()).toMatch(/^•+$/);

    await window.click('#reveal-private-key');
    await expect(privateKey).not.toHaveClass(/masked/);
    expect(await privateKey.textContent()).toContain('"iv"');

    await window.click('#reveal-private-key');
    await expect(privateKey).toHaveClass(/masked/);
    expect(await privateKey.textContent()).toMatch(/^•+$/);

    expect(errors).toEqual([]);
});

test('the RSA password field is masked and rejects a weak password with a message', async () => {
    await navigateTo(window, SCREENS.rsa.nav, SCREENS.rsa.heading);

    await expect(window.locator('#password')).toHaveAttribute('type', 'password');

    await window.fill('#password', 'weak');
    await window.click('#generate-button');

    await expect(window.locator('#generate-rsa-result-container .note.danger')).toContainText('special symbol');
    await expect(window.locator('#generated-rsa-private-key-result')).toHaveCount(0);

    expect(errors).toEqual([]);
});
