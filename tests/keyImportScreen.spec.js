'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const {test, expect} = require('@playwright/test');

const {launchApp, navigateTo, stubFileDialog, SCREENS} = require('./helpers');
const {CURVE} = require('../src/lib/enumerations/curve');
const {
    SEATS,
    clientRsaKey,
    buildBackupPackage,
    buildNodeKeys,
    buildTicket,
    buildTwoAlgorithmTicket,
    buildMigrationTicket,
    servedTicket,
    buildBackupPackageForSession,
} = require('./keyImportFixture');

let electronApp, window, errors, fixtureDir, ticketPath, backupPath, rsaPath;
let migrationTicketPath, seatWithoutAKeyTicketPath;
let twoAlgorithmTicketPath, eddsaBackupPath;
let servedTicketPath, servedEcdsaBackupPath, servedEddsaBackupPath;

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

    // The ticket the Dashboard actually serves, written out exactly as the client downloads it,
    // from the copy tests/fixtures/key-import-ticket.json holds in both repos. Every other file
    // above is a ticket this process invented.
    const served = servedTicket('recovery');
    const [servedEcdsaSession, servedEddsaSession] = served.keyImportMetadata;
    const servedEcdsaBackup = buildBackupPackageForSession(servedEcdsaSession);
    const servedEddsaBackup = buildBackupPackageForSession(servedEddsaSession);

    servedTicketPath = path.join(fixtureDir, 'served_ticket.json');
    servedEcdsaBackupPath = path.join(fixtureDir, 'served_backup.json');
    servedEddsaBackupPath = path.join(fixtureDir, 'served_backup_eddsa.json');

    fs.writeFileSync(servedTicketPath, JSON.stringify(served, null, 4));
    fs.writeFileSync(servedEcdsaBackupPath, JSON.stringify(servedEcdsaBackup.data));
    fs.writeFileSync(servedEddsaBackupPath, JSON.stringify(servedEddsaBackup.data));
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

// WHY THERE IS NO "the screen seals and offers a file to download" TEST HERE. The screen runs the
// REAL service, which seals VAULTODY's own seats to the node keys compiled into the build - and
// this repo ships that table EMPTY on purpose (src/lib/vaultodyNodePublicKeys.js), because no
// placeholder is safer than a refusal. So an unpinned build cannot seal ANY ticket, and the two
// tests below assert exactly that, for a single-key vault, a two-key vault and a migration alike.
//
// When a release engineer fills the production keys in, these flip back into the success-path
// tests they were: sealed part counts, the summary line, the algorithms list and the download
// button. Until then the sealing itself is covered end to end in tests/keyImport.spec.js, which
// constructs the service with a pinned pair of its own.
test('an unpinned build refuses every ticket, blaming the build and not the client\'s files', async () => {
    const runs = [
        {ticket: ticketPath, backups: backupPath},
        {ticket: twoAlgorithmTicketPath, backups: [backupPath, eddsaBackupPath]},
        {ticket: migrationTicketPath, backups: backupPath},
    ];

    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');
    await chooseFileAt('#rsaFileButton', rsaPath);

    for (const run of runs) {
        await chooseFileAt('#ticketFileButton', run.ticket);
        await chooseFileAt('#recoveryDataFileButton', run.backups);

        await window.click('#sealButton');

        await expect(window.locator('.result-card h3')).toContainText('Sealing failed');
        await expect(window.locator('#keyImportError'))
            .toContainText("built without VAULTODY's own node keys");
        // It says whose fault it is, because "get a different build" and "choose a different
        // file" are very different instructions to be given in an emergency.
        await expect(window.locator('#keyImportError')).toContainText('fault in the tool itself');
        await expect(window.locator('#download-sealed')).toHaveCount(0);
    }

    expect(errors).toEqual([]);
});

test('the screen says which VAULTODY keys this build carries, before any file is chosen', async () => {
    // The client's half of the eye-check the ceremony asks for: the Dashboard shows its copy of
    // these keys, this screen shows the build's, and the two have to read the same. A build
    // carrying none says THAT instead, rather than an empty list that reads like "fine".
    await expect(window.locator('#keyImportPinnedMissing')).toContainText('cannot seal anything');
    await expect(window.locator('#keyImportPinnedMissing'))
        .toContainText('will not take them from the ticket');
    await expect(window.locator('#keyImportPinnedKeys')).toHaveCount(0);

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

test('the ticket the Dashboard actually serves is accepted, and gets as far as the pinning', async () => {
    // The drift this settles was invisible from either side: the tool read a ticket shape the
    // Dashboard did not serve, and every suite stayed green because each built its own. This run
    // drives the shared file end to end through the screen the client really uses.
    await chooseFileAt('#ticketFileButton', servedTicketPath);
    await expect(window.locator('#ticketFilePicker')).toHaveClass(/loaded/);
    await expect(window.locator('#ticketFileStatus')).toContainText('accepted');

    await window.selectOption('#privateKeySelect', 'rawPemPrivateKey');
    await chooseFileAt('#recoveryDataFileButton', [servedEcdsaBackupPath, servedEddsaBackupPath]);
    await chooseFileAt('#rsaFileButton', rsaPath);

    await window.click('#sealButton');

    // The refusal is about the BUILD, not about the files: the served ticket passed the shape
    // gate, the roster check and the package check, and stopped only at the pinned table this
    // repo ships empty. "Download the ticket again" here would mean the shape had drifted.
    await expect(window.locator('.result-card h3')).toContainText('Sealing failed');
    await expect(window.locator('#keyImportError'))
        .toContainText("built without VAULTODY's own node keys");
    await expect(window.locator('#keyImportError')).not.toContainText('Download the ticket again');
    await expect(window.locator('#download-sealed')).toHaveCount(0);

    expect(errors).toEqual([]);
});
