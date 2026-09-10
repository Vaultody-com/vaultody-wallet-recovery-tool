'use strict';

const crypto = require('crypto');
const fs = require('fs');
const {test, expect} = require('@playwright/test');

const envelope = require('../src/lib/utils/keyImportEnvelope');
const generator = require('./vectors/generateKeyImportEnvelopeVectors');

const VECTORS = JSON.parse(fs.readFileSync(generator.OUTPUT_FILE).toString());

// The api caps the publicKey DTO field at 66 hex characters, which an uncompressed SEC1 key
// (130 characters) cannot even reach the node through.
const API_PUBLIC_KEY_HEX_LIMIT = 66;

/**
 * @param {string} name
 * @return {object}
 */
function vectorCase(name) {
    const found = VECTORS.cases.find(one => one.name === name);
    if (found === undefined) {
        throw new Error(`no vector case named ${name}`);
    }

    return found;
}

const RECOVERY_ECDSA = vectorCase('recovery-ecdsa');
const RECOVERY_EDDSA = vectorCase('recovery-eddsa');
const MIGRATION_ECDSA = vectorCase('migration-ecdsa');

/**
 * Flips the last nibble of a hex string, leaving its byte length alone — a tamper the length
 * checks cannot catch, so what refuses it can only be the GCM tag.
 *
 * @param {string} hex
 * @return {string}
 */
function flipLastNibble(hex) {
    return hex.slice(0, -1) + (hex.slice(-1) === '0' ? '1' : '0');
}

/**
 * @param {object} testCase
 * @param {object} overrides
 * @return {object}
 */
function seal(testCase, overrides = {}) {
    return envelope.sealPoint({
        point: testCase.input.pointHex,
        recipientPublicKey: VECTORS.recipient.publicKeyPkixBase64,
        sessionId: Buffer.from(testCase.input.sessionIdHex, 'hex'),
        binding: testCase.input.binding,
        ...overrides,
    });
}

/**
 * @param {object} testCase
 * @param {object} sealed
 * @param {object} overrides
 * @return {Buffer}
 */
function open(testCase, sealed, overrides = {}) {
    return envelope.openEnvelope({
        senderPublicKey: sealed.senderPublicKey,
        payload: sealed.payload,
        recipientPrivateKey: generator.RECIPIENT_PRIVATE_KEY_PEM,
        sessionId: Buffer.from(testCase.input.sessionIdHex, 'hex'),
        binding: testCase.input.binding,
        ...overrides,
    });
}

test('the checked-in test vectors are exactly what the sealer produces', () => {
    // The vectors file is what the Go side is tested against, so it must never drift from the
    // implementation without someone noticing here first.
    expect(generator.buildVectors()).toEqual(VECTORS);
});

test('the vectors cover both kinds on both curves', () => {
    expect(VECTORS.cases.map(one => one.name)).toEqual([
        'recovery-ecdsa',
        'recovery-eddsa',
        'migration-ecdsa',
        'migration-eddsa',
    ]);

    // No two cases may share a (KEK, nonce) pair, or the file would be publishing a GCM misuse.
    const kekAndNonce = VECTORS.cases.map(one => `${one.expected.kekHex}:${one.input.nonceHex}`);
    expect(new Set(kekAndNonce).size).toBe(VECTORS.cases.length);
});

test('the retired public key is the compressed point, never the uncompressed one', () => {
    for (const testCase of [RECOVERY_ECDSA, RECOVERY_EDDSA]) {
        const publicKey = testCase.input.binding.publicKey;
        const expectedLength = envelope.RETIRED_PUBLIC_KEY_BYTES_LENGTH[testCase.input.binding.algorithm];

        expect(Buffer.from(publicKey, 'hex').length, testCase.name).toBe(expectedLength);
        // Derived through the same encoder the tool uses, not typed in by hand.
        expect(publicKey).toBe(testCase.input.retiredKey.encodedHex);
        expect(publicKey.length).toBeLessThanOrEqual(API_PUBLIC_KEY_HEX_LIMIT);
    }

    expect(Buffer.from(RECOVERY_ECDSA.input.binding.publicKey, 'hex').length).toBe(33);
    expect([0x02, 0x03]).toContain(Buffer.from(RECOVERY_ECDSA.input.binding.publicKey, 'hex')[0]);
    expect(Buffer.from(RECOVERY_EDDSA.input.binding.publicKey, 'hex').length).toBe(32);
});

test('a migration binding carries no anchor at all', () => {
    for (const testCase of VECTORS.cases.filter(one => one.input.binding.kind === 'migration')) {
        expect(testCase.input.binding.oldKeyId, testCase.name).toBe('');
        expect(testCase.input.binding.publicKey, testCase.name).toBe('');
        expect(testCase.input.binding.oldThreshold, testCase.name).toBe(0);
        expect(testCase.input.retiredKey, testCase.name).toBeNull();
        // The chain code is the SUPPLIED one, and is still bound.
        expect(testCase.input.binding.chainCode.length, testCase.name).toBeGreaterThan(0);
    }
});

for (const name of ['recovery-ecdsa', 'recovery-eddsa', 'migration-ecdsa', 'migration-eddsa']) {
    test(`${name}: the vector payload is nonce || ciphertext || tag and opens to the point`, () => {
        const testCase = vectorCase(name);
        const payload = Buffer.from(testCase.expected.payload, 'base64');

        expect(payload.length).toBe(12 + 32 + 16);
        expect(payload.subarray(0, 12).toString('hex')).toBe(testCase.input.nonceHex);
        expect(payload.subarray(12, 44).toString('hex')).toBe(testCase.expected.ciphertextHex);
        expect(payload.subarray(44).toString('hex')).toBe(testCase.expected.authTagHex);

        const sealed = {
            senderPublicKey: testCase.expected.senderPublicKey,
            payload: testCase.expected.payload,
        };

        expect(open(testCase, sealed).toString('hex')).toBe(testCase.input.pointHex);
        expect(envelope.computeBinding(testCase.input.binding).toString('hex'))
            .toBe(testCase.expected.bindingDigestHex);
    });

    test(`${name}: senderPublicKey is the PKIX DER of the ephemeral public half`, () => {
        const testCase = vectorCase(name);
        const senderPublicKey = crypto.createPublicKey({
            key: Buffer.from(testCase.expected.senderPublicKey, 'base64'),
            format: 'der',
            type: 'spki',
        });

        expect(senderPublicKey.asymmetricKeyDetails.namedCurve).toBe('prime256v1');
        expect(senderPublicKey.export({type: 'spki', format: 'der'}).toString('base64'))
            .toBe(testCase.input.ephemeral.publicKeyPkixBase64);
    });
}

test('every case produces a distinct binding digest', () => {
    const digests = VECTORS.cases.map(one => one.expected.bindingDigestHex);

    expect(new Set(digests).size).toBe(VECTORS.cases.length);
});

test('the KEK label separates an envelope from a node-to-node ceremony frame', () => {
    const sessionId = Buffer.from(RECOVERY_ECDSA.input.sessionIdHex, 'hex');
    const ephemeral = crypto.createPrivateKey(RECOVERY_ECDSA.input.ephemeral.privateKeyPem);
    const recipient = crypto.createPublicKey(generator.RECIPIENT_PRIVATE_KEY_PEM);

    const {sharedSecret, kek} = envelope.deriveKek(ephemeral, recipient, sessionId);

    // What utils.DeriveSharedKey computes for the SAME ECDH secret and session: no label.
    const ceremonyKey = Buffer.from(crypto.hkdfSync(
        'sha256',
        sharedSecret,
        Buffer.alloc(0),
        Buffer.from(sessionId.toString('hex'), 'ascii'),
        32
    ));

    expect(kek.toString('hex')).toBe(RECOVERY_ECDSA.expected.kekHex);
    expect(kek.equals(ceremonyKey)).toBe(false);
});

test('every element of a recovery binding is load-bearing', () => {
    for (const testCase of [RECOVERY_ECDSA, RECOVERY_EDDSA]) {
        const base = testCase.input.binding;
        const sealed = seal(testCase);
        // Each tamper is itself VALID, so what refuses it is the GCM tag and not a length or
        // shape check that a node could be talked into skipping.
        const tampered = {
            keyId: '00000000-0000-4000-8000-000000000000',
            oldKeyId: '00000000-0000-4000-8000-000000000001',
            importerIndex: base.importerIndex + 1,
            newThreshold: base.newThreshold + 1,
            oldThreshold: base.oldThreshold + 1,
            publicKey: flipLastNibble(base.publicKey),
            chainCode: flipLastNibble(base.chainCode),
        };

        expect(open(testCase, sealed).toString('hex')).toBe(testCase.input.pointHex);

        for (const [field, value] of Object.entries(tampered)) {
            const binding = {...base, [field]: value};

            expect(() => envelope.computeBinding(binding), `${testCase.name}: ${field}`).not.toThrow();
            expect(
                () => open(testCase, sealed, {binding: binding}),
                `${testCase.name}: ${field} is not bound`
            ).toThrow();
        }
    }
});

test('algorithm is load-bearing even where no public key pins it', () => {
    // On the migration path the public key is empty, so nothing but the algorithm element itself
    // separates an ecdsa import from an eddsa one.
    const sealed = seal(MIGRATION_ECDSA);
    const binding = {...MIGRATION_ECDSA.input.binding, algorithm: 'eddsa'};

    expect(open(MIGRATION_ECDSA, sealed).toString('hex')).toBe(MIGRATION_ECDSA.input.pointHex);
    expect(() => envelope.computeBinding(binding)).not.toThrow();
    expect(() => open(MIGRATION_ECDSA, sealed, {binding: binding})).toThrow();
});

test('kind is bound, so a recovery envelope cannot be replayed into a migration', () => {
    const recoverySealed = seal(RECOVERY_ECDSA);
    const migrationShaped = {
        ...RECOVERY_ECDSA.input.binding,
        kind: 'migration',
        oldKeyId: '',
        oldThreshold: 0,
        publicKey: '',
    };

    // The migration path requires no retired-key row, so without kind in the binding this is
    // exactly the downgrade that would let an import skip its only non-circular check. Both
    // shapes are perfectly valid bindings — only the tag tells them apart.
    expect(() => envelope.computeBinding(migrationShaped)).not.toThrow();
    expect(() => open(RECOVERY_ECDSA, recoverySealed, {binding: migrationShaped})).toThrow();

    const migrationSealed = seal(MIGRATION_ECDSA);
    const recoveryShaped = {
        ...MIGRATION_ECDSA.input.binding,
        kind: 'recovery',
        oldKeyId: RECOVERY_ECDSA.input.binding.oldKeyId,
        oldThreshold: RECOVERY_ECDSA.input.binding.oldThreshold,
        publicKey: RECOVERY_ECDSA.input.binding.publicKey,
    };

    expect(() => envelope.computeBinding(recoveryShaped)).not.toThrow();
    expect(() => open(MIGRATION_ECDSA, migrationSealed, {binding: recoveryShaped})).toThrow();
});

test('a replay into another ceremony fails', () => {
    const sealed = seal(RECOVERY_ECDSA);
    const otherSession = Buffer.from('00000000000000000000000000000000', 'hex');

    expect(() => open(RECOVERY_ECDSA, sealed, {sessionId: otherSession})).toThrow();
});

test('an envelope addressed to one node cannot be opened by another', () => {
    const otherNode = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
    const sealed = seal(RECOVERY_ECDSA);

    expect(() => open(RECOVERY_ECDSA, sealed, {recipientPrivateKey: otherNode.privateKey})).toThrow();
});

test('two seals of the same point differ, so nothing is deterministic on the wire', () => {
    const first = seal(RECOVERY_ECDSA);
    const second = seal(RECOVERY_ECDSA);

    expect(first.senderPublicKey).not.toBe(second.senderPublicKey);
    expect(first.payload).not.toBe(second.payload);
    expect(open(RECOVERY_ECDSA, first).toString('hex')).toBe(RECOVERY_ECDSA.input.pointHex);
    expect(open(RECOVERY_ECDSA, second).toString('hex')).toBe(RECOVERY_ECDSA.input.pointHex);
});

test('the binding is length-prefixed, so adjacent fields cannot be slid into each other', () => {
    const base = RECOVERY_ECDSA.input.binding;
    // "3" || "32" vs "33" || "2": identical if the elements are simply concatenated.
    const left = envelope.computeBinding({...base, importerIndex: 3, newThreshold: 32});
    const right = envelope.computeBinding({...base, importerIndex: 33, newThreshold: 2});

    expect(left.equals(right)).toBe(false);
});

test('an uncompressed retired public key is refused, not re-encoded', () => {
    const base = RECOVERY_ECDSA.input.binding;
    // The 65-byte uncompressed SEC1 form of the very same point. Guessing the encoding here is
    // what would let the tool pin a digest mpc-node can never reproduce.
    const uncompressed = `04${'11'.repeat(64)}`;

    expect(() => seal(RECOVERY_ECDSA, {binding: {...base, publicKey: uncompressed}}))
        .toThrow('binding.publicKey must be the 33-byte compressed ecdsa point, got 65 bytes');

    // A 32-byte ed25519-shaped key on the ecdsa path, and a 33-byte ecdsa-shaped one on the
    // eddsa path: both the right length for the OTHER curve, both refused.
    expect(() => seal(RECOVERY_ECDSA, {binding: {...base, publicKey: '11'.repeat(32)}}))
        .toThrow('binding.publicKey must be the 33-byte compressed ecdsa point, got 32 bytes');
    expect(() => seal(RECOVERY_EDDSA, {
        binding: {...RECOVERY_EDDSA.input.binding, publicKey: `02${'11'.repeat(32)}`},
    })).toThrow('binding.publicKey must be the 32-byte compressed eddsa point, got 33 bytes');
});

test('the two kinds refuse each other\'s shape', () => {
    const recovery = RECOVERY_ECDSA.input.binding;
    const migration = MIGRATION_ECDSA.input.binding;

    expect(() => envelope.computeBinding({...recovery, oldKeyId: ''}))
        .toThrow('binding.oldKeyId must be a non-empty string on the recovery path');
    expect(() => envelope.computeBinding({...migration, oldKeyId: recovery.oldKeyId}))
        .toThrow('binding.oldKeyId must be empty on the migration path');
    expect(() => envelope.computeBinding({...migration, publicKey: recovery.publicKey}))
        .toThrow('binding.publicKey must be empty on the migration path');
    expect(() => envelope.computeBinding({...migration, oldThreshold: 2}))
        .toThrow('binding.oldThreshold must be 0 on the migration path');
    expect(() => envelope.computeBinding({...recovery, kind: 'reshare'}))
        .toThrow('binding.kind must be one of');
    expect(() => envelope.computeBinding({...recovery, kind: undefined}))
        .toThrow('binding.kind must be one of');
});

test('a retired 1-of-n threshold is legitimate, an unknown 0 is not', () => {
    const base = RECOVERY_ECDSA.input.binding;

    // Every row written by the pre-fix importer carries 0, which means "unknown", never
    // "matches" — the recovery path must refuse it rather than seal a binding nobody can check.
    expect(() => envelope.computeBinding({...base, oldThreshold: 0}))
        .toThrow('binding.oldThreshold must be an integer of at least 1');
    expect(() => envelope.computeBinding({...base, newThreshold: 0}))
        .toThrow('binding.newThreshold must be an integer of at least 1');

    expect(envelope.computeBinding({...base, oldThreshold: 1}).length).toBe(32);
    // The eddsa vector is a real 1-of-n restore, sealed and opened end to end.
    expect(RECOVERY_EDDSA.input.binding.oldThreshold).toBe(1);
    expect(open(RECOVERY_EDDSA, seal(RECOVERY_EDDSA)).toString('hex'))
        .toBe(RECOVERY_EDDSA.input.pointHex);
});

test('malformed inputs are refused instead of sealed', () => {
    const base = RECOVERY_ECDSA.input.binding;

    expect(() => seal(RECOVERY_ECDSA, {point: '00'.repeat(31)})).toThrow('point must be exactly 32 bytes');
    expect(() => seal(RECOVERY_ECDSA, {nonce: '00'.repeat(11)})).toThrow('nonce must be exactly 12 bytes');
    expect(() => seal(RECOVERY_ECDSA, {sessionId: Buffer.alloc(0)})).toThrow('sessionId must not be empty');
    expect(() => seal(RECOVERY_ECDSA, {binding: {...base, algorithm: 'schnorr'}}))
        .toThrow('binding.algorithm must be one of');
    expect(() => seal(RECOVERY_ECDSA, {binding: {...base, importerIndex: -1}}))
        .toThrow('binding.importerIndex must be a non-negative integer');
    expect(() => seal(RECOVERY_ECDSA, {binding: {...base, keyId: ''}}))
        .toThrow('binding.keyId must be a non-empty string');
    expect(() => seal(RECOVERY_ECDSA, {binding: {...base, chainCode: ''}}))
        .toThrow('binding.chainCode must not be empty');

    // An RSA recipient key is the shape someone would reach for out of habit; mpc-node's
    // identity key is EC P-256 and nothing else.
    const rsa = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    expect(() => seal(RECOVERY_ECDSA, {recipientPublicKey: rsa.publicKey})).toThrow('must be an EC public key');

    const p384 = crypto.generateKeyPairSync('ec', {namedCurve: 'secp384r1'});
    expect(() => seal(RECOVERY_ECDSA, {recipientPublicKey: p384.publicKey})).toThrow('must be on prime256v1');
});
