'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const {test, expect} = require('@playwright/test');

const {launchApp, navigateTo, stubFileDialog, SCREENS} = require('./helpers');
const {CURVE} = require('../src/lib/enumerations/curve');
const {
    SEATS,
    VAULT_ID,
    clientRsaKey,
    buildBackupPackage,
    buildNodeKeys,
    buildTicket,
    buildTwoAlgorithmTicket,
    buildMigrationTicket,
} = require('./keyImportFixture');

let electronApp, window, errors, fixtureDir, ticketPath, backupPath, rsaPath;
let migrationTicketPath, seatWithoutAKeyTicketPath, declaredPublicKey;
let twoAlgorithmTicketPath, eddsaBackupPath;

/**
 * Drives the native open-file dialog stub with an absolute path - or with several, for the
 * backup picker, which takes one file per algorithm on the ticket.
 *
 * @param {string} buttonSelector
 * @param {string|string[]} filePath
 */
async function chooseFileAt(buttonSelector, filePath) {
    await electronApp.evaluate((_electron, chosen) => {
        globalThis.__testFilePath = chosen;
    }, filePath);

    await window.click(buttonSelector);
}

test.beforeAll(() => {
    const backup = buildBackupPackage();
    const eddsaBackup = buildBackupPackage({}, CURVE.ED25519);
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const migrationTicket = buildMigrationTicket(nodeKeys, backup);
    // The vault that forced this: two keys, two sessions, and an upload that is only accepted
    // if it carries both.
    const twoAlgorithmTicket = buildTwoAlgorithmTicket(nodeKeys);

    // A ticket that passes every shape check and still cannot be sealed: one seat's node has
    // no public key on it, so that part has nowhere to go.
    const seatWithoutAKeyTicket = buildTicket(nodeKeys);
    seatWithoutAKeyTicket.keyImportMetadata[0].players[SEATS[2]] = '';

    declaredPublicKey = backup.compressedPublicKey;

    fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vaultody-key-import-'));
    ticketPath = path.join(fixtureDir, 'ticket.json');
    migrationTicketPath = path.join(fixtureDir, 'migration_ticket.json');
    seatWithoutAKeyTicketPath = path.join(fixtureDir, 'seat_without_a_key_ticket.json');
    twoAlgorithmTicketPath = path.join(fixtureDir, 'two_algorithm_ticket.json');
    backupPath = path.join(fixtureDir, 'backup.json');
    eddsaBackupPath = path.join(fixtureDir, 'backup_eddsa.json');
    rsaPath = path.join(fixtureDir, 'rsa_private_key.pem');

    fs.writeFileSync(ticketPath, JSON.stringify(ticket));
    fs.writeFileSync(migrationTicketPath, JSON.stringify(migrationTicket));
    fs.writeFileSync(seatWithoutAKeyTicketPath, JSON.stringify(seatWithoutAKeyTicket));
    fs.writeFileSync(twoAlgorithmTicketPath, JSON.stringify(twoAlgorithmTicket));
    fs.writeFileSync(backupPath, JSON.stringify(backup.data));
    fs.writeFileSync(eddsaBackupPath, JSON.stringify(eddsaBackup.data));
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

test('the screen says which formats it accepts before anything is chosen', async () => {
    await expect(window.locator('#key-import-accepts')).toContainText('VAULTODY backup data files');
    await expect(window.locator('#key-import-accepts')).toContainText('shamir');
    // The word "migration" promises more than this screen does, so the screen says what it
    // actually means before the client starts a ceremony they cannot finish.
    await expect(window.locator('#key-import-accepts'))
        .toContainText('another custody provider is a different format and cannot be sealed here');

    expect(errors).toEqual([]);
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
    await expect(window.locator('#keyImportSummary')).toContainText('recovery');
    await expect(window.locator('#keyImportSummary')).toContainText(`key_import_${VAULT_ID}.json`);
    await expect(window.locator('#keyImportAlgorithms')).toContainText('ecdsa');
    await expect(window.locator('#keyImportAlgorithms')).toContainText('seats #0, #1, #3');
    await expect(window.locator('#download-sealed')).toBeVisible();

    expect(errors).toEqual([]);
});

test('a two-algorithm vault is sealed in one run, into one file naming no algorithm', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFileAt('#ticketFileButton', twoAlgorithmTicketPath);
    // Both backup files at once: the Dashboard refuses an upload that is short an algorithm, so
    // running the tool twice and merging two files by hand is not a workaround, it is the bug.
    await chooseFileAt('#recoveryDataFileButton', [backupPath, eddsaBackupPath]);
    await chooseFileAt('#rsaFileButton', rsaPath);

    await window.click('#sealButton');

    await expect(window.locator('.result-card h3')).toContainText(`Sealed ${SEATS.length * 2} part(s)`);
    await expect(window.locator('#keyImportSummary')).toContainText(`key_import_${VAULT_ID}.json`);
    await expect(window.locator('#keyImportAlgorithms')).toContainText('ecdsa');
    await expect(window.locator('#keyImportAlgorithms')).toContainText('eddsa');

    expect(errors).toEqual([]);
});

test('a ticket covering both keys refuses a run that brings only one backup file', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFileAt('#ticketFileButton', twoAlgorithmTicketPath);
    await chooseFileAt('#recoveryDataFileButton', backupPath);
    await chooseFileAt('#rsaFileButton', rsaPath);

    await window.click('#sealButton');

    await expect(window.locator('.result-card h3')).toContainText('Sealing failed');
    await expect(window.locator('#keyImportError')).toContainText('No backup data file was given for eddsa');
    await expect(window.locator('#download-sealed')).toHaveCount(0);

    expect(errors).toEqual([]);
});

test('a file that is not a VAULTODY backup package is refused by name', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFileAt('#ticketFileButton', ticketPath);
    // A perfectly good JSON file, and not a backup package - which is what an export from
    // another custodian looks like to this screen.
    await chooseFileAt('#recoveryDataFileButton', ticketPath);
    await chooseFileAt('#rsaFileButton', rsaPath);

    await window.click('#sealButton');

    await expect(window.locator('.result-card h3')).toContainText('Sealing failed');
    await expect(window.locator('#keyImportError')).toContainText('is not a VAULTODY backup data file');
    await expect(window.locator('#keyImportError')).toContainText('another custodian');

    expect(errors).toEqual([]);
});

test('a migration shows back the key the ticket declared it was sealed against', async () => {
    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');

    await chooseFileAt('#ticketFileButton', migrationTicketPath);
    await chooseFileAt('#recoveryDataFileButton', backupPath);
    await chooseFileAt('#rsaFileButton', rsaPath);

    await window.click('#sealButton');

    await expect(window.locator('#keyImportSummary')).toContainText('migration');
    await expect(window.locator('#keyImportDeclaredKeys')).toContainText(`ecdsa`);
    await expect(window.locator('#keyImportDeclaredKeys')).toContainText(declaredPublicKey);

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
