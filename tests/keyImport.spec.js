'use strict';

const crypto = require('crypto');
const BN = require('bn.js');
const {test, expect} = require('@playwright/test');

const KeyImportService = require('../src/lib/services/keyImportService');
const RecoveryDataEntity = require('../src/lib/entities/recoveryDataEntity');
const Validator = require('../src/validation/validator');
const envelope = require('../src/lib/utils/keyImportEnvelope');
const curveUtils = require('../src/lib/utils/curve');
const lagrange = require('../src/lib/utils/lagrange');
const privateKeyTypeEnum = require('../src/lib/enumerations/privateKeyType');
const {CURVE, DOMAIN_PARAMS} = require('../src/lib/enumerations/curve');
const {
    SEATS,
    OLD_THRESHOLD,
    NEW_THRESHOLD,
    KEY_ID,
    OLD_KEY_ID,
    EDDSA_KEY_ID,
    clientRsaKey,
    toPaddedHex,
    buildBackupPackage,
    buildNodeKeys,
    buildTicket,
    buildTwoAlgorithmTicket,
    buildMigrationTicket,
    buildTwoAlgorithmMigrationTicket,
} = require('./keyImportFixture');

const domainParams = DOMAIN_PARAMS[CURVE.SECP256K1];

/**
 * @param {object} ticket
 * @param {...object} backups one per algorithm the ticket lists
 * @return {object}
 */
function seal(ticket, ...backups) {
    return new KeyImportService().sealKeyParts(
        ticket,
        backups.map(backup => new RecoveryDataEntity(backup.data)),
        Buffer.from(clientRsaKey.privateKey),
        privateKeyTypeEnum.RAW_PEM
    );
}

/**
 * Opens one sealed part at the node that owns its seat, rebuilding the binding from the ticket
 * and the package the way an mpc-node does.
 *
 * @param {object} part
 * @param {object} metadata the session of the part's own algorithm
 * @param {Map<number, {privateKey: object}>} nodeKeys
 * @param {object} backup
 * @param {object} bindingOverrides
 * @return {Buffer}
 */
function openPart(part, metadata, nodeKeys, backup, bindingOverrides = {}) {
    return envelope.openEnvelope({
        senderPublicKey: part.senderPublicKey,
        payload: part.payload,
        recipientPrivateKey: nodeKeys.get(part.index).privateKey,
        sessionId: metadata.sessionId,
        binding: {
            kind: envelope.KIND.RECOVERY,
            keyId: metadata.keyId,
            oldKeyId: metadata.oldKeyId,
            algorithm: part.algorithm,
            importerIndex: part.index,
            newThreshold: NEW_THRESHOLD,
            oldThreshold: OLD_THRESHOLD,
            publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
            chainCode: backup.chainCode,
            ...bindingOverrides,
        },
    });
}

test('every seat in the ticket gets an envelope only its own node can open', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);

    expect(result.keys).toHaveLength(1);
    expect(result.keys[0].seats).toEqual(SEATS);
    // A recovery declares nothing: both bound values are read off the package, and every node
    // re-reads them from its own row for the retired key.
    expect(result.keys[0].declaredPublicKey).toBeNull();
    expect(result.keys[0].algorithm).toBe(envelope.ALGORITHM.ECDSA);
    expect(result.keys[0].keyId).toBe(KEY_ID);

    const binding = {
        kind: envelope.KIND.RECOVERY,
        keyId: KEY_ID,
        oldKeyId: OLD_KEY_ID,
        algorithm: envelope.ALGORITHM.ECDSA,
        newThreshold: NEW_THRESHOLD,
        oldThreshold: OLD_THRESHOLD,
        publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
        chainCode: backup.chainCode,
    };

    for (const part of result.sealedParts) {
        // The node rebuilds the binding from its OWN index, so the envelope only opens under
        // the index it was addressed to.
        const point = envelope.openEnvelope({
            senderPublicKey: part.senderPublicKey,
            payload: part.payload,
            recipientPrivateKey: nodeKeys.get(part.index).privateKey,
            sessionId: metadata.sessionId,
            binding: {...binding, importerIndex: part.index},
        });

        expect(point.toString('hex')).toBe(toPaddedHex(backup.shares.get(part.index)));
    }
});

test('an envelope addressed to one seat does not open at another', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);
    const [first] = result.sealedParts;

    expect(() => envelope.openEnvelope({
        senderPublicKey: first.senderPublicKey,
        payload: first.payload,
        recipientPrivateKey: nodeKeys.get(SEATS[1]).privateKey,
        sessionId: metadata.sessionId,
        binding: {
            kind: envelope.KIND.RECOVERY,
            keyId: KEY_ID,
            oldKeyId: OLD_KEY_ID,
            algorithm: envelope.ALGORITHM.ECDSA,
            importerIndex: SEATS[1],
            newThreshold: NEW_THRESHOLD,
            oldThreshold: OLD_THRESHOLD,
            publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
            chainCode: backup.chainCode,
        },
    })).toThrow();
});

test('the sealed points still interpolate to the key the package was made from', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);

    const indices = [];
    const values = [];
    for (const part of result.sealedParts) {
        const point = envelope.openEnvelope({
            senderPublicKey: part.senderPublicKey,
            payload: part.payload,
            recipientPrivateKey: nodeKeys.get(part.index).privateKey,
            sessionId: metadata.sessionId,
            binding: {
                kind: envelope.KIND.RECOVERY,
                keyId: KEY_ID,
                oldKeyId: OLD_KEY_ID,
                algorithm: envelope.ALGORITHM.ECDSA,
                importerIndex: part.index,
                newThreshold: NEW_THRESHOLD,
                oldThreshold: OLD_THRESHOLD,
                publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
                chainCode: backup.chainCode,
            },
        });

        // The abscissa is the seat plus one, the same convention recoverPrivateKey uses.
        indices.push(new BN(part.index + 1));
        values.push(new BN(point));
    }

    const reconstructed = lagrange.reconstruct(indices, values, domainParams.n);

    expect(reconstructed.toString('hex')).toBe(backup.secret.toString('hex'));
    // And the sealing itself never had to form it: the retired group public key is read off the
    // package, not derived from a reassembled secret.
    expect(new RecoveryDataEntity(backup.data).getCompressedPublicKey().toString('hex'))
        .toBe(curveUtils.encodePoint(CURVE.SECP256K1, domainParams.g.mul(backup.secret)).toString('hex'));
});

test('a package whose parts are not polynomial points is refused, not silently sealed', () => {
    const backup = buildBackupPackage({sharing_type: 'multiplicative'});
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket, backup)).toThrow(/shamir/);
    // And the refusal names the format the tool does want, rather than only what is wrong.
    expect(() => seal(ticket, backup)).toThrow(/VAULTODY backup data file/);
});

test('a ticket for the other algorithm is refused, naming the file that is missing', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys(), {algorithm: envelope.ALGORITHM.EDDSA});

    // The ticket wants eddsa and the client brought secp256k1: both halves of the mismatch are
    // named, because either file could be the wrong one.
    expect(() => seal(ticket, backup)).toThrow(/No backup data file was given for eddsa/);
});

test('a ticket with no session id is refused rather than sealed to nothing', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys(), {sessionId: ''});

    expect(() => seal(ticket, backup)).toThrow(/sessionId/);
});

test('a session id that is not hex is refused, because the node hex-decodes it', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys(), {sessionId: 'not-a-session-id'});

    expect(() => seal(ticket, backup)).toThrow(/sessionId/);
});

test('a ticket whose kind is not one this tool seals for is refused, not treated as a migration', () => {
    const backup = buildBackupPackage();
    const ticket = {...buildTicket(buildNodeKeys()), kind: 'restore'};

    expect(() => seal(ticket, backup)).toThrow(/"restore"/);
});

test('a seat with no node public key is refused before anything is sealed', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    ticket.keyImportMetadata[0].players[SEATS[1]] = '';

    expect(() => seal(ticket, backup)).toThrow(new RegExp(`no public key for seat #${SEATS[1]}`));
});

test('a package that is short one of the seats the ticket names is refused', () => {
    const backup = buildBackupPackage();
    backup.data.key_parts = backup.data.key_parts.slice(0, 1);
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket, backup)).toThrow(
        /asks for 3 ecdsa parts and the ecdsa backup data file holds no part for seat #1, seat #3/
    );
});

test('a ticket asking for fewer seats than the retired key needed is refused', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys(), {oldThreshold: SEATS.length + 1});

    expect(() => seal(ticket, backup)).toThrow(new RegExp(`needs ${SEATS.length + 1} parts`));
});

test('a shared/ERS package, whose parts name no seat, is refused', () => {
    const backup = buildBackupPackage();
    backup.data.key_parts = backup.data.key_parts.map(part => ({...part, index: null}));
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket, backup)).toThrow(/no part for any seat/);
});

test('a migration seals against the chain code the TICKET declares, not the package\'s', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    // The node binds the chain code it was HANDED on a migration - there is no row to read one
    // from - so a tool that bound the package's would produce envelopes nothing can open. The
    // two are deliberately different here, which is the only way to tell which one was used.
    const declaredChainCode = crypto.randomBytes(32).toString('hex');
    const ticket = buildMigrationTicket(nodeKeys, {...backup, chainCode: declaredChainCode});
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);

    expect(result.kind).toBe(envelope.KIND.MIGRATION);
    expect(result.keys[0].seats).toEqual(SEATS);
    expect(result.keys[0].declaredPublicKey).toBe(backup.compressedPublicKey);
    expect(declaredChainCode).not.toBe(backup.chainCode);

    // A migration binds no retired key at all: no old key id, no old threshold, no public key.
    const binding = {
        kind: envelope.KIND.MIGRATION,
        keyId: KEY_ID,
        algorithm: envelope.ALGORITHM.ECDSA,
        newThreshold: NEW_THRESHOLD,
        chainCode: declaredChainCode,
    };

    for (const part of result.sealedParts) {
        const point = envelope.openEnvelope({
            senderPublicKey: part.senderPublicKey,
            payload: part.payload,
            recipientPrivateKey: nodeKeys.get(part.index).privateKey,
            sessionId: metadata.sessionId,
            binding: {...binding, importerIndex: part.index},
        });

        expect(point.toString('hex')).toBe(toPaddedHex(backup.shares.get(part.index)));

        // And the package's own chain code is NOT what it was sealed against.
        expect(() => envelope.openEnvelope({
            senderPublicKey: part.senderPublicKey,
            payload: part.payload,
            recipientPrivateKey: nodeKeys.get(part.index).privateKey,
            sessionId: metadata.sessionId,
            binding: {...binding, importerIndex: part.index, chainCode: backup.chainCode},
        })).toThrow();
    }
});

test('a migration ticket that declares no key for the algorithm is refused', () => {
    const backup = buildBackupPackage();
    const ticket = buildMigrationTicket(buildNodeKeys(), backup);
    ticket.externalKeys = [];

    expect(() => seal(ticket, backup)).toThrow(/does not say which ecdsa key is being brought in/);
});

test('a migration ticket declaring a different key from the backup file is refused', () => {
    const backup = buildBackupPackage();
    const otherKey = buildBackupPackage().compressedPublicKey;
    const ticket = buildMigrationTicket(buildNodeKeys(), backup, {publicKey: otherKey});

    // Every node rebuilds the group key from the parts and compares it with the declared one,
    // so this ceremony can only end in a refusal - it just ends in one hours later.
    expect(() => seal(ticket, backup)).toThrow(/not the same key/);
});

test('a migration ticket declaring an uncompressed public key is refused', () => {
    const backup = buildBackupPackage();
    const uncompressed = Buffer.from(domainParams.g.mul(backup.secret).encode('array', false)).toString('hex');
    const ticket = buildMigrationTicket(buildNodeKeys(), backup, {publicKey: uncompressed});

    expect(() => seal(ticket, backup)).toThrow(/66-character compressed public key/);
});

test('the ticket constraints accept a well-formed ticket and refuse a broken one', () => {
    const validator = new Validator();
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const migrationTicket = buildMigrationTicket(nodeKeys, backup);

    expect(validator.validateKeyImportTicket(ticket)).toBeUndefined();
    expect(validator.validateKeyImportTicket(migrationTicket)).toBeUndefined();
    expect(validator.validateKeyImportTicket({...ticket, kind: 'whatever'})).toBeDefined();
    expect(validator.validateKeyImportTicket({...ticket, keyImportMetadata: []})).toBeDefined();
    expect(validator.validateKeyImportTicket({
        ...migrationTicket,
        externalKeys: [{algorithm: envelope.ALGORITHM.ECDSA, chainCode: 'zz', publicKey: ''}],
    })).toBeDefined();
});

// ---------------------------------------------------------------------------------------------
// One ticket, every algorithm. vaults-manager's completeKeyImport walks each algorithm on the
// ticket and refuses the upload if any of them is short a seat, so a vault holding both an ecdsa
// and an eddsa key can only ever be completed by ONE file carrying both.
// ---------------------------------------------------------------------------------------------

test('one run seals every algorithm the ticket lists, into one set of parts', () => {
    const ecdsaBackup = buildBackupPackage();
    const eddsaBackup = buildBackupPackage({}, CURVE.ED25519);
    const nodeKeys = buildNodeKeys();
    const ticket = buildTwoAlgorithmTicket(nodeKeys);

    const result = seal(ticket, ecdsaBackup, eddsaBackup);

    expect(result.keys.map(key => key.algorithm))
        .toEqual([envelope.ALGORITHM.ECDSA, envelope.ALGORITHM.EDDSA]);
    // Two independent keys, each with its own id — not one key sealed twice.
    expect(result.keys.map(key => key.keyId)).toEqual([KEY_ID, EDDSA_KEY_ID]);
    expect(result.sealedParts).toHaveLength(SEATS.length * 2);

    const backups = {
        [envelope.ALGORITHM.ECDSA]: ecdsaBackup,
        [envelope.ALGORITHM.EDDSA]: eddsaBackup,
    };

    for (const metadata of ticket.keyImportMetadata) {
        const backup = backups[metadata.algorithm];
        const parts = result.sealedParts.filter(part => part.algorithm === metadata.algorithm);

        expect(parts.map(part => part.index)).toEqual(SEATS);

        for (const part of parts) {
            const point = openPart(part, metadata, nodeKeys, backup);

            expect(point.toString('hex')).toBe(toPaddedHex(backup.shares.get(part.index)));
        }
    }
});

test('each algorithm is sealed under its OWN session, so the two cannot be crossed', () => {
    const ecdsaBackup = buildBackupPackage();
    const eddsaBackup = buildBackupPackage({}, CURVE.ED25519);
    const nodeKeys = buildNodeKeys();
    const ticket = buildTwoAlgorithmTicket(nodeKeys);
    const [ecdsaSession, eddsaSession] = ticket.keyImportMetadata;

    const result = seal(ticket, ecdsaBackup, eddsaBackup);
    const [eddsaPart] = result.sealedParts.filter(part => part.algorithm === envelope.ALGORITHM.EDDSA);

    expect(openPart(eddsaPart, eddsaSession, nodeKeys, eddsaBackup).length).toBe(32);
    // The envelope key is derived over the session id, and the two algorithms have different
    // ones, so an eddsa part does not open in the ecdsa session even at the right node.
    expect(() => openPart(eddsaPart, ecdsaSession, nodeKeys, eddsaBackup)).toThrow();
});

test('a ticket listing an algorithm with no backup package names the missing one', () => {
    const ecdsaBackup = buildBackupPackage();
    const ticket = buildTwoAlgorithmTicket(buildNodeKeys());

    expect(() => seal(ticket, ecdsaBackup)).toThrow(/backup data file was given for eddsa/);
});

test('a backup package for an algorithm the ticket does not list is refused, not ignored', () => {
    const ecdsaBackup = buildBackupPackage();
    const eddsaBackup = buildBackupPackage({}, CURVE.ED25519);
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket, ecdsaBackup, eddsaBackup)).toThrow(/include eddsa, but this ticket imports only the ecdsa key/);
});

test('two backup packages on the same curve are refused rather than one of them winning', () => {
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket, buildBackupPackage(), buildBackupPackage()))
        .toThrow(/Two of the backup data files hold an ecdsa key/);
});

test('no backup package at all is refused with the format the tool wants', () => {
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket)).toThrow(/No backup data file was given/);
    expect(() => seal(ticket)).toThrow(/VAULTODY backup data file/);
});

test('a package short a seat the ticket lists is still refused, and the algorithm is named', () => {
    const ecdsaBackup = buildBackupPackage();
    const eddsaBackup = buildBackupPackage({}, CURVE.ED25519);
    // The eddsa backup predates the co-signer joining, so it has no part for seat #3 — the
    // ecdsa one is complete, and sealing only what is coverable would hand the Dashboard a file
    // it refuses, after the ceremony had already been started.
    eddsaBackup.data.key_parts = eddsaBackup.data.key_parts.filter(part => part.index !== SEATS[2]);
    const ticket = buildTwoAlgorithmTicket(buildNodeKeys());

    expect(() => seal(ticket, ecdsaBackup, eddsaBackup))
        .toThrow(new RegExp(`eddsa parts and the eddsa backup data file holds no part for seat #${SEATS[2]}`));
});

test('a migration of a two-algorithm vault seals both declared keys in one run', () => {
    const ecdsaBackup = buildBackupPackage();
    const eddsaBackup = buildBackupPackage({}, CURVE.ED25519);
    const nodeKeys = buildNodeKeys();
    const ticket = buildTwoAlgorithmMigrationTicket(nodeKeys, ecdsaBackup, eddsaBackup);

    const result = seal(ticket, ecdsaBackup, eddsaBackup);

    expect(result.kind).toBe(envelope.KIND.MIGRATION);
    expect(result.keys.map(key => key.declaredPublicKey))
        .toEqual([ecdsaBackup.compressedPublicKey, eddsaBackup.compressedPublicKey]);
    expect(result.sealedParts).toHaveLength(SEATS.length * 2);
});

// ---------------------------------------------------------------------------------------------
// "Migration" does not widen the input format. It means only that VAULTODY holds no row for the
// key being imported, so the two bound values are declared on the ticket instead of read from a
// node. The package itself is still a VAULTODY backup, and anything else is refused by name.
// ---------------------------------------------------------------------------------------------

test('a migration still demands the VAULTODY backup format, and says so', () => {
    const backup = buildBackupPackage({sharing_type: 'additive'});
    const ticket = buildMigrationTicket(buildNodeKeys(), backup);

    expect(() => seal(ticket, backup)).toThrow(/shamir/);
    expect(() => seal(ticket, backup)).toThrow(/VAULTODY backup data file/);
});

test('a migration refuses a package whose parts name no seat, naming the format it wanted', () => {
    const backup = buildBackupPackage();
    backup.data.key_parts = backup.data.key_parts.map(part => ({...part, index: null}));
    const ticket = buildMigrationTicket(buildNodeKeys(), backup);

    expect(() => seal(ticket, backup)).toThrow(/no part for any seat/);
    expect(() => seal(ticket, backup)).toThrow(/VAULTODY backup data file/);
});
