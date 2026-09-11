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
const nodeKeyPinning = require('../src/lib/vaultodyNodePublicKeys');
const {MPC_CUSTODY_SCHEME} = require('../src/lib/enumerations/mpcCustodyScheme');
const {
    SEATS,
    MOBILE_SEATS,
    OLD_THRESHOLD,
    NEW_THRESHOLD,
    KEY_ID,
    OLD_KEY_ID,
    EDDSA_KEY_ID,
    clientRsaKey,
    toPaddedHex,
    buildBackupPackage,
    buildNodeKeys,
    generateNodeKey,
    pinnedNodePublicKeys,
    servedTicket,
    servedSeats,
    pinnedFromServedTicket,
    buildBackupPackageForSession,
    buildTicket,
    buildTwoAlgorithmTicket,
    buildMigrationTicket,
    buildTwoAlgorithmMigrationTicket,
} = require('./keyImportFixture');

const domainParams = DOMAIN_PARAMS[CURVE.SECP256K1];

/**
 * Seals with a service built the way a signed RELEASE build is: VAULTODY's own two node keys
 * compiled in, and the ticket's copy of them treated as something to compare against. The fixture
 * is the deployment these tickets come from, so its pinned pair is the pair the tickets name.
 *
 * @param {object} ticket
 * @param {...object} backups one per algorithm the ticket lists
 * @return {object}
 */
function seal(ticket, ...backups) {
    return sealWith(new KeyImportService(pinnedNodePublicKeys()), ticket, ...backups);
}

/**
 * The same run against a service pinned to something else - a build cut with different keys, a
 * build cut with none at all.
 *
 * @param {KeyImportService} service
 * @param {object} ticket
 * @param {...object} backups
 * @return {object}
 */
function sealWith(service, ticket, ...backups) {
    return service.sealKeyParts(
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

// ---------------------------------------------------------------------------------------------
// WHERE THE RECIPIENT COMES FROM. The ticket is a file downloaded from a web dashboard, so it is
// exactly the run-time online value the encrypting side must not learn its recipient from:
// substitute the file and you substitute the node every part is locked for. VAULTODY's own two
// seats are therefore pinned in the build and the ticket's copy of them is only ever compared.
// The client's own seats keep coming off the ticket, because the client generated those keys and
// is the only party who can vouch for them.
// ---------------------------------------------------------------------------------------------

test('a VAULTODY seat is sealed to the key in the BUILD, not the one on the ticket', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);
    const part = result.sealedParts.find(sealed => sealed.index === 0);

    // The pinned pair and the ticket's copy agree here, so the run goes through - and the part
    // opens under the pinned node's own private key, which is the only thing that proves which
    // value was actually used.
    const point = envelope.openEnvelope({
        senderPublicKey: part.senderPublicKey,
        payload: part.payload,
        recipientPrivateKey: nodeKeys.get(0).privateKey,
        sessionId: metadata.sessionId,
        binding: {
            kind: envelope.KIND.RECOVERY,
            keyId: KEY_ID,
            oldKeyId: OLD_KEY_ID,
            algorithm: envelope.ALGORITHM.ECDSA,
            importerIndex: 0,
            newThreshold: NEW_THRESHOLD,
            oldThreshold: OLD_THRESHOLD,
            publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
            chainCode: backup.chainCode,
        },
    });

    expect(point.toString('hex')).toBe(toPaddedHex(backup.shares.get(0)));
});

test('a ticket naming a different key for a VAULTODY seat is refused, not sealed to', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    // The whole attack in one line: a ticket that reaches the client with someone else's key on
    // VAULTODY's seat. Every part of the vault's key would be locked for whoever put it there.
    const attacker = generateNodeKey();
    ticket.keyImportMetadata[0].players[0] = attacker.publicKey;

    expect(() => seal(ticket, backup)).toThrow(/does not match the keys this tool was built with/);
    // And it tells a non-engineer what to do about it, which is not "try again".
    expect(() => seal(ticket, backup)).toThrow(/Do not try again and do not upload anything/);
    expect(() => seal(ticket, backup)).toThrow(/contact VAULTODY/);
    // Both readings are quoted, so the client and support can compare the same two things.
    expect(() => seal(ticket, backup)).toThrow(/this tool: .+, this ticket: /);
});

test('the refusal names the seat by who owns it, not by a player number alone', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys());
    ticket.keyImportMetadata[0].players[1] = generateNodeKey().publicKey;

    expect(() => seal(ticket, backup)).toThrow(/seat #1 \(VAULTODY node 1\)/);
});

test("the client's own co-signer seat still comes from the ticket, and is sealed to", () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];
    // Seat 3's key is generated when the client stands their own node up - long after this build
    // was cut - so it CANNOT be pinned, and the party who generated it is the party who vouches
    // for it. A ticket naming a different one for that seat is the client's own business.
    const replacement = generateNodeKey();
    metadata.players[3] = replacement.publicKey;

    const result = seal(ticket, backup);
    const part = result.sealedParts.find(sealed => sealed.index === 3);

    const point = envelope.openEnvelope({
        senderPublicKey: part.senderPublicKey,
        payload: part.payload,
        recipientPrivateKey: replacement.privateKey,
        sessionId: metadata.sessionId,
        binding: {
            kind: envelope.KIND.RECOVERY,
            keyId: KEY_ID,
            oldKeyId: OLD_KEY_ID,
            algorithm: envelope.ALGORITHM.ECDSA,
            importerIndex: 3,
            newThreshold: NEW_THRESHOLD,
            oldThreshold: OLD_THRESHOLD,
            publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
            chainCode: backup.chainCode,
        },
    });

    expect(point.toString('hex')).toBe(toPaddedHex(backup.shares.get(3)));
});

test('a build that pins nothing refuses to seal, and names what a release build must carry', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys());

    // What this repo ships: an empty table. A tool that sealed to a placeholder would lock the
    // client's key parts for nobody, or worse, for somebody.
    const unpinned = new KeyImportService({});

    expect(() => sealWith(unpinned, ticket, backup))
        .toThrow(/built without VAULTODY's own node keys/);
    expect(() => sealWith(unpinned, ticket, backup)).toThrow(/will not guess/);
    expect(() => sealWith(unpinned, ticket, backup)).toThrow(/vaultodyNodePublicKeys\.js/);
});

test('a pinned entry that is not a P-256 key counts as no key at all', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys());
    const rsa = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {type: 'spki', format: 'der'},
        privateKeyEncoding: {type: 'pkcs8', format: 'der'},
    });

    // A fat-fingered release edit must not read as a pinned key. It is not one, and the build is
    // refused in the same words as a build that pins nothing.
    const misconfigured = new KeyImportService({
        0: 'not a key at all',
        1: rsa.publicKey.toString('base64'),
    });

    expect(() => sealWith(misconfigured, ticket, backup))
        .toThrow(/built without VAULTODY's own node keys/);
});

test('whatever this build pins, every pinned value is a real node key', () => {
    // The guard on the release edit itself: the table ships empty, and the first thing that ever
    // goes into it must be a P-256 SubjectPublicKeyInfo, not a fingerprint, a hex string or a
    // placeholder left in by accident.
    for (const [seat, value] of Object.entries(nodeKeyPinning.PINNED_NODE_PUBLIC_KEYS)) {
        expect(nodeKeyPinning.canonicalPublicKey(value),
            `pinned key for seat #${seat} is not a P-256 public key`).not.toBeNull();
    }

    // And the seats it is the authority on are VAULTODY's own two, nobody else's.
    expect([...nodeKeyPinning.PINNED_SEATS]).toEqual([0, 1]);
});

test('what the build pins is readable back, for the eye-check the ceremony asks for', () => {
    const pinned = pinnedNodePublicKeys();
    const shown = new KeyImportService(pinned).pinnedNodeKeys();

    expect(shown.complete).toBe(true);
    expect(shown.seats.map(seat => seat.index)).toEqual([0, 1]);
    expect(shown.seats[0].publicKey).toBe(pinned[0]);
    expect(shown.seats[0].name).toBe('VAULTODY node 0');
    expect(shown.seats[0].fingerprint).toMatch(/^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/);

    // A build carrying none says so, rather than showing an empty list that reads like "fine".
    expect(new KeyImportService({}).pinnedNodeKeys().complete).toBe(false);
});

// ---------------------------------------------------------------------------------------------
// WHICH VAULTS v1 COVERS: mobile_cosigner and server_cosigner. full_custody and hybrid are out,
// and are refused HERE - a client who seals a ticket the Dashboard will refuse has spent an
// offline ceremony on nothing.
// ---------------------------------------------------------------------------------------------

test('a mobile_cosigner vault is sealed, seat 2 included', () => {
    const backup = buildBackupPackage({}, CURVE.SECP256K1, MOBILE_SEATS);
    const nodeKeys = buildNodeKeys(MOBILE_SEATS);
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);

    expect(result.keys[0].seats).toEqual(MOBILE_SEATS);
    expect(result.keys[0].scheme).toBe(MPC_CUSTODY_SCHEME.MOBILE_COSIGNER);
    expect(result.sealedParts.map(part => part.index)).toEqual(MOBILE_SEATS);

    // The handset's envelope is sealed like any other, to the key the ticket carries for it -
    // that key is generated on the device and cannot be in any build.
    const part = result.sealedParts.find(sealed => sealed.index === 2);
    const point = envelope.openEnvelope({
        senderPublicKey: part.senderPublicKey,
        payload: part.payload,
        recipientPrivateKey: nodeKeys.get(2).privateKey,
        sessionId: metadata.sessionId,
        binding: {
            kind: envelope.KIND.RECOVERY,
            keyId: KEY_ID,
            oldKeyId: OLD_KEY_ID,
            algorithm: envelope.ALGORITHM.ECDSA,
            importerIndex: 2,
            newThreshold: NEW_THRESHOLD,
            oldThreshold: OLD_THRESHOLD,
            publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
            chainCode: backup.chainCode,
        },
    });

    expect(point.toString('hex')).toBe(toPaddedHex(backup.shares.get(2)));
});

test('a server_cosigner vault reports the scheme it was sealed under', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys());

    expect(seal(ticket, backup).keys[0].scheme).toBe(MPC_CUSTODY_SCHEME.SERVER_COSIGNER);
});

test('a full_custody ticket is refused by name, not sealed for a ceremony nobody will accept', () => {
    const seats = [0, 1];
    const backup = buildBackupPackage({}, CURVE.SECP256K1, seats);
    const ticket = buildTicket(buildNodeKeys(seats), {threshold: 2});

    expect(() => seal(ticket, backup)).toThrow(/"full_custody"/);
    expect(() => seal(ticket, backup)).toThrow(/vault VAULTODY holds on its own/);
    expect(() => seal(ticket, backup)).toThrow(/Nothing has been sealed/);
});

test('a hybrid ticket is refused explicitly, rather than falling out of the seat code', () => {
    const seats = [0, 1, 2, 3];
    const backup = buildBackupPackage({}, CURVE.SECP256K1, seats);
    const ticket = buildTicket(buildNodeKeys(seats), {threshold: 4});

    expect(() => seal(ticket, backup)).toThrow(/"hybrid"/);
    expect(() => seal(ticket, backup)).toThrow(/does not cover it/);
});

test('a roster VAULTODY does not issue at all is refused, naming the two it does', () => {
    const seats = [0, 1, 5];
    const backup = buildBackupPackage({}, CURVE.SECP256K1, seats);
    const ticket = buildTicket(buildNodeKeys(seats));

    expect(() => seal(ticket, backup)).toThrow(/not a set of players VAULTODY issues/);
    expect(() => seal(ticket, backup)).toThrow(/seat #0, seat #1 and seat #2/);
    expect(() => seal(ticket, backup)).toThrow(/seat #0, seat #1 and seat #3/);
});

// ---------------------------------------------------------------------------------------------
// THE TICKET THE DASHBOARD ACTUALLY SERVES.
//
// Everything above builds its ticket in this process, and vaultody-dashboard-backend's suite
// builds its own on the other side - which is precisely how the two ended up green about a shape
// they disagreed on. tests/fixtures/key-import-ticket.json is the one copy, committed byte for
// byte in both repos: the Dashboard asserts that what it renders IS that file, and the tests
// below seal FROM it. Rename a field on either side and the other side goes red, which is the
// whole reason the file exists.
//
// The shape is the PROTO's, not either service's: vaults_manager.proto declares
// KeyImportTicket.key_import_metadata and KeyImportSessionMetadata.players as a
// map<uint32, StringValue>, so a session list is `keyImportMetadata` and a roster is an object
// keyed by seat index - never `sessions`, never an array of {index, publicKey} pairs.
// ---------------------------------------------------------------------------------------------

/**
 * Seals a served ticket the way a release build cut for the deployment that ticket names would:
 * VAULTODY's own two seats pinned to the keys the FILE carries for them.
 *
 * @param {object} ticket
 * @param {...object} backups
 * @return {object}
 */
function sealServed(ticket, ...backups) {
    return sealWith(new KeyImportService(pinnedFromServedTicket()), ticket, ...backups);
}

test('the served ticket is the proto\'s shape: keyImportMetadata, and players keyed by seat', () => {
    const ticket = servedTicket('recovery');

    // The two halves of the drift this file settles, asserted by name.
    expect(Array.isArray(ticket.keyImportMetadata)).toBe(true);
    expect(ticket.sessions).toBeUndefined();

    const players = ticket.keyImportMetadata[0].players;
    expect(Array.isArray(players)).toBe(false);
    expect(Object.keys(players).sort()).toEqual(['0', '1', '3']);

    // And every value under a seat is a key a part can actually be locked to, rather than an
    // object holding one.
    for (const value of Object.values(players)) {
        expect(nodeKeyPinning.canonicalPublicKey(value)).not.toBeNull();
    }
});

test('the shape gate accepts the served ticket exactly as it is downloaded', () => {
    const validator = new Validator();

    expect(validator.validateKeyImportTicket(servedTicket('recovery'))).toBeUndefined();
    expect(validator.validateKeyImportTicket(servedTicket('migration'))).toBeUndefined();
});

// The rule this ticket shares with the two fixtures that pin the rest of the ceremony -
// fixtures/mpc-key-import.json in vaultody-blockchain-signer-grpc-messages and
// fixtures/key-import-mobile-arm.fixture.json in vaultody-vaults-grpc-messages, reconciled
// against each other in vaults-manager's keyImportFixtureFamilies.test.js. The new key is cut
// one share per seat, and blockchain-signer's drive refuses anything else outright. A served
// ticket carrying a lower threshold is a file this tool would spend a whole offline session
// sealing against, for a ceremony that is refused at the last step.
test('every session of the served ticket is cut one share per seat', () => {
    for (const name of ['recovery', 'migration']) {
        for (const session of servedTicket(name).keyImportMetadata) {
            expect(session.threshold).toBe(servedSeats(session).length);
        }
    }
});

test('a real downloaded ticket seals every seat of every algorithm it lists', () => {
    const ticket = servedTicket('recovery');
    const [ecdsaSession, eddsaSession] = ticket.keyImportMetadata;
    const seats = servedSeats(ecdsaSession);
    const ecdsaBackup = buildBackupPackageForSession(ecdsaSession);
    const eddsaBackup = buildBackupPackageForSession(eddsaSession);

    const result = sealServed(ticket, ecdsaBackup, eddsaBackup);

    expect(result.vaultId).toBe(ticket.vaultId);
    expect(result.kind).toBe(envelope.KIND.RECOVERY);
    expect(result.keys.map(key => key.algorithm))
        .toEqual([envelope.ALGORITHM.ECDSA, envelope.ALGORITHM.EDDSA]);
    // The key ids come off the file, so a ticket that stopped carrying them - or carried them
    // under another name - could not produce this.
    expect(result.keys.map(key => key.keyId)).toEqual([ecdsaSession.keyId, eddsaSession.keyId]);
    expect(result.keys.map(key => key.seats)).toEqual([seats, seats]);
    expect(result.keys.map(key => key.scheme))
        .toEqual([MPC_CUSTODY_SCHEME.SERVER_COSIGNER, MPC_CUSTODY_SCHEME.SERVER_COSIGNER]);
    // A recovery declares no key: both bound values are read off the package.
    expect(result.keys.every(key => key.declaredPublicKey === null)).toBe(true);

    expect(result.sealedParts).toHaveLength(seats.length * 2);
    for (const part of result.sealedParts) {
        expect(seats).toContain(part.index);
        // Each envelope is addressed with a real ephemeral P-256 key and carries
        // nonce || ciphertext || tag, which is only produced once the recipient's key off the
        // file has been parsed and an ECDH secret derived against it.
        expect(nodeKeyPinning.canonicalPublicKey(part.senderPublicKey)).not.toBeNull();
        expect(Buffer.from(part.payload, 'base64').length)
            .toBe(envelope.GCM_NONCE_BYTES_LENGTH + envelope.POINT_BYTES_LENGTH + envelope.GCM_TAG_BYTES_LENGTH);
    }

    const ecdsaParts = result.sealedParts.filter(part => part.algorithm === envelope.ALGORITHM.ECDSA);
    expect(ecdsaParts.map(part => part.index)).toEqual(seats);
});

test('pinning finally meets a real ticket: a substituted VAULTODY seat on it is refused', () => {
    const ticket = servedTicket('recovery');
    const [ecdsaSession, eddsaSession] = ticket.keyImportMetadata;
    const ecdsaBackup = buildBackupPackageForSession(ecdsaSession);
    const eddsaBackup = buildBackupPackageForSession(eddsaSession);
    // The attack, on the file the client really downloads: one seat of the roster swapped for
    // somebody else's key between the Dashboard and the tool.
    ecdsaSession.players['0'] = generateNodeKey().publicKey;

    const attempt = () => sealServed(ticket, ecdsaBackup, eddsaBackup);

    expect(attempt).toThrow(/does not match the keys this tool was built with/);
    expect(attempt).toThrow(/seat #0 \(VAULTODY node 0\)/);
    // Both fingerprints, so the client and support compare the same two readings.
    expect(attempt).toThrow(/this tool: .+, this ticket: /);
    expect(attempt).toThrow(/Do not try again and do not upload anything/);
});

test("a real ticket's client-held seat is still taken from the ticket, not refused", () => {
    const ticket = servedTicket('recovery');
    const [ecdsaSession, eddsaSession] = ticket.keyImportMetadata;
    const ecdsaBackup = buildBackupPackageForSession(ecdsaSession);
    const eddsaBackup = buildBackupPackageForSession(eddsaSession);
    // Seat 3 is the client's own co-signer: they generated that key and are the party who
    // vouches for it, so a served ticket naming a different one still seals.
    const replacement = generateNodeKey();
    ecdsaSession.players['3'] = replacement.publicKey;

    const result = sealServed(ticket, ecdsaBackup, eddsaBackup);
    const part = result.sealedParts
        .find(sealed => sealed.algorithm === envelope.ALGORITHM.ECDSA && sealed.index === 3);

    const point = envelope.openEnvelope({
        senderPublicKey: part.senderPublicKey,
        payload: part.payload,
        recipientPrivateKey: replacement.privateKey,
        sessionId: ecdsaSession.sessionId,
        binding: {
            kind: envelope.KIND.RECOVERY,
            keyId: ecdsaSession.keyId,
            oldKeyId: ecdsaSession.oldKeyId,
            algorithm: envelope.ALGORITHM.ECDSA,
            importerIndex: 3,
            newThreshold: ecdsaSession.threshold,
            oldThreshold: ecdsaSession.oldThreshold,
            publicKey: new RecoveryDataEntity(ecdsaBackup.data).getCompressedPublicKey(),
            chainCode: ecdsaBackup.chainCode,
        },
    });

    // Sealed under the session id, key ids and thresholds the FILE carries: rebuild the binding
    // from anything else and the GCM tag fails.
    expect(point.toString('hex')).toBe(toPaddedHex(ecdsaBackup.shares.get(3)));
});

test('a served migration ticket carries its declared key through to the key comparison', () => {
    const ticket = servedTicket('migration');
    const [session] = ticket.keyImportMetadata;
    const backup = buildBackupPackageForSession(session);

    // A mobile_cosigner roster, read off the file's own players map.
    expect(servedSeats(session)).toEqual([0, 1, nodeKeyPinning.SEAT.MOBILE_DEVICE]);

    // The declared key reaches the comparison against the package, which is the last thing a
    // migration is checked on - and this backup is a different key, so it is refused by both
    // readings rather than sealed.
    const attempt = () => sealServed(ticket, backup);

    expect(attempt).toThrow(new RegExp(`The ticket is for the ecdsa key ${ticket.externalKeys[0].publicKey}`));
    expect(attempt).toThrow(/They are not the same key/);
});

test('a served migration ticket whose declared key IS the package seals under that chain code', () => {
    const ticket = servedTicket('migration');
    const [session] = ticket.keyImportMetadata;
    const backup = buildBackupPackageForSession(session);
    // The one value a static file cannot carry: the key the client is actually bringing in. The
    // rest of the ticket - roster, session id, key id, threshold, kind - is the served file's.
    ticket.externalKeys[0].publicKey = backup.compressedPublicKey;

    const result = sealServed(ticket, backup);

    expect(result.kind).toBe(envelope.KIND.MIGRATION);
    expect(result.keys[0].scheme).toBe(MPC_CUSTODY_SCHEME.MOBILE_COSIGNER);
    expect(result.keys[0].keyId).toBe(session.keyId);
    expect(result.keys[0].declaredPublicKey).toBe(backup.compressedPublicKey);
    expect(result.sealedParts.map(part => part.index)).toEqual([0, 1, nodeKeyPinning.SEAT.MOBILE_DEVICE]);
});
