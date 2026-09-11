'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const {test, expect} = require('@playwright/test');

const {launchApp, navigateTo, stubFileDialog, SCREENS} = require('./helpers');
const {
    SEATS,
    clientRsaKey,
    buildBackupPackage,
    buildNodeKeys,
    buildTicket,
    buildMigrationTicket,
} = require('./keyImportFixture');

let electronApp, window, errors, fixtureDir, ticketPath, backupPath, rsaPath;
let migrationTicketPath, seatWithoutAKeyTicketPath, declaredPublicKey;

/**
 * Drives the native open-file dialog stub with an absolute path, so a test can feed three
 * different pickers on one screen.
 *
 * @param {string} buttonSelector
 * @param {string} filePath
 */
async function chooseFileAt(buttonSelector, filePath) {
    await electronApp.evaluate((_electron, chosen) => {
        globalThis.__testFilePath = chosen;
    }, filePath);

    await window.click(buttonSelector);
}

test.beforeAll(() => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const migrationTicket = buildMigrationTicket(nodeKeys, backup);

    // A ticket that passes every shape check and still cannot be sealed: one seat's node has
    // no public key on it, so that part has nowhere to go.
    const seatWithoutAKeyTicket = buildTicket(nodeKeys);
    seatWithoutAKeyTicket.keyImportMetadata[0].players[SEATS[2]] = '';

    declaredPublicKey = backup.compressedPublicKey;

    fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-key-import-'));
    ticketPath = path.join(fixtureDir, 'ticket.json');
    migrationTicketPath = path.join(fixtureDir, 'migration_ticket.json');
    seatWithoutAKeyTicketPath = path.join(fixtureDir, 'seat_without_a_key_ticket.json');
    backupPath = path.join(fixtureDir, 'backup.json');
    rsaPath = path.join(fixtureDir, 'rsa_private_key.pem');

    fs.writeFileSync(ticketPath, JSON.stringify(ticket));
    fs.writeFileSync(migrationTicketPath, JSON.stringify(migrationTicket));
    fs.writeFileSync(seatWithoutAKeyTicketPath, JSON.stringify(seatWithoutAKeyTicket));
    fs.writeFileSync(backupPath, JSON.stringify(backup.data));
    fs.writeFileSync(rsaPath, clientRsaKey.privateKey);
});

test.afterAll(() => {
    fs.rmSync(fixtureDir, {recursive: true, force: true});
});

test.beforeEach(async () => {
    ({electronApp, window, errors} = await launchApp());
    await stubFileDialog(electronApp);
    await navigateTo(window, SCREENS.keyImport.nav, SCREENS.keyImport.heading);
});

test.afterEach(async () => {
    await electronApp?.close();
});

test('each chosen file reports whether it was accepted', async () => {
    await chooseFileAt('#ticketFileButton', ticketPath);
    await expect(window.locator('#ticketFilePicker')).toHaveClass(/loaded/);
    await expect(window.locator('#ticketFileStatus')).toContainText('accepted');

    // An RSA key is a valid file but not a ticket.
    await chooseFileAt('#ticketFileButton', rsaPath);
    await expect(window.locator('#ticketFilePicker')).toHaveClass(/invalid/);
    await expect(window.locator('#ticketFileStatus')).toContainText('rejected');

    expect(errors).toEqual([]);
});

test('the screen seals every seat in the ticket and offers one file to upload', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFileAt('#ticketFileButton', ticketPath);
    await chooseFileAt('#recoveryDataFileButton', backupPath);
    await chooseFileAt('#rsaFileButton', rsaPath);

    await window.click('#sealButton');

    await expect(window.locator('.result-card h3')).toContainText(`Sealed ${SEATS.length} part(s)`);
    await expect(window.locator('#keyImportSummary')).toContainText('ecdsa · recovery');
    await expect(window.locator('#keyImportSummary')).toContainText('seats #0, #1, #3');
    await expect(window.locator('#download-sealed')).toBeVisible();

    expect(errors).toEqual([]);
});

test('a migration shows back the key the ticket declared it was sealed against', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFileAt('#ticketFileButton', migrationTicketPath);
    await chooseFileAt('#recoveryDataFileButton', backupPath);
    await chooseFileAt('#rsaFileButton', rsaPath);

    await window.click('#sealButton');

    await expect(window.locator('#keyImportSummary')).toContainText('ecdsa · migration');
    await expect(window.locator('#keyImportDeclaredKey')).toHaveText(declaredPublicKey);

    expect(errors).toEqual([]);
});

test('a seat with no node public key is refused in words the client can act on', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFileAt('#ticketFileButton', seatWithoutAKeyTicketPath);
    await chooseFileAt('#recoveryDataFileButton', backupPath);
    await chooseFileAt('#rsaFileButton', rsaPath);

    await window.click('#sealButton');

    await expect(window.locator('.result-card h3')).toContainText('Sealing failed');
    await expect(window.locator('#keyImportError')).toContainText(`no public key for seat #${SEATS[2]}`);
    await expect(window.locator('#keyImportError')).toContainText('Download the ticket again');
    await expect(window.locator('#download-sealed')).toHaveCount(0);

    expect(errors).toEqual([]);
});

test('a wrong RSA key fails with a readable message instead of a half-sealed file', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFileAt('#ticketFileButton', ticketPath);
    await chooseFileAt('#recoveryDataFileButton', backupPath);
    // The ticket is a perfectly good JSON file and a perfectly bad private key.
    await chooseFileAt('#rsaFileButton', ticketPath);

    await window.click('#sealButton');

    await expect(window.locator('.result-card h3')).toContainText('Sealing failed');
    await expect(window.locator('#download-sealed')).toHaveCount(0);

    expect(errors).toEqual([]);
});
