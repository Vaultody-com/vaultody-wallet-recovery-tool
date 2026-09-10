'use strict';

const crypto = require('crypto');
const fs = require('fs');
const {test, expect} = require('@playwright/test');

const envelope = require('../src/lib/utils/keyImportEnvelope');
const generator = require('./vectors/generateKeyImportEnvelopeVectors');

const VECTORS = JSON.parse(fs.readFileSync(generator.OUTPUT_FILE).toString());

/**
 * @param {object} overrides
 * @return {object}
 */
function seal(overrides = {}) {
    return envelope.sealPoint({
        point: VECTORS.input.pointHex,
        recipientPublicKey: VECTORS.input.recipient.publicKeyPkixBase64,
        sessionId: Buffer.from(VECTORS.input.sessionIdHex, 'hex'),
        binding: VECTORS.input.binding,
        ...overrides,
    });
}

/**
 * @param {object} sealed
 * @param {object} overrides
 * @return {Buffer}
 */
function open(sealed, overrides = {}) {
    return envelope.openEnvelope({
        senderPublicKey: sealed.senderPublicKey,
        payload: sealed.payload,
        recipientPrivateKey: generator.RECIPIENT_PRIVATE_KEY_PEM,
        sessionId: Buffer.from(VECTORS.input.sessionIdHex, 'hex'),
        binding: VECTORS.input.binding,
        ...overrides,
    });
}

test('the checked-in test vectors are exactly what the sealer produces', () => {
    // The vectors file is what the Go side is tested against, so it must never drift from the
    // implementation without someone noticing here first.
    expect(generator.buildVectors()).toEqual(VECTORS);
});

test('the vector payload is nonce || ciphertext || tag and opens to the point', () => {
    const payload = Buffer.from(VECTORS.expected.payload, 'base64');

    expect(payload.length).toBe(12 + 32 + 16);
    expect(payload.subarray(0, 12).toString('hex')).toBe(VECTORS.input.nonceHex);
    expect(payload.subarray(12, 44).toString('hex')).toBe(VECTORS.expected.ciphertextHex);
    expect(payload.subarray(44).toString('hex')).toBe(VECTORS.expected.authTagHex);

    const sealed = {
        senderPublicKey: VECTORS.expected.senderPublicKey,
        payload: VECTORS.expected.payload,
    };

    expect(open(sealed).toString('hex')).toBe(VECTORS.input.pointHex);
});

test('senderPublicKey is the PKIX DER of the ephemeral public half', () => {
    const senderPublicKey = crypto.createPublicKey({
        key: Buffer.from(VECTORS.expected.senderPublicKey, 'base64'),
        format: 'der',
        type: 'spki',
    });

    expect(senderPublicKey.asymmetricKeyDetails.namedCurve).toBe('prime256v1');
    expect(senderPublicKey.export({type: 'spki', format: 'der'}).toString('base64'))
        .toBe(VECTORS.input.ephemeral.publicKeyPkixBase64);
});

test('the KEK label separates an envelope from a node-to-node ceremony frame', () => {
    const sessionId = Buffer.from(VECTORS.input.sessionIdHex, 'hex');
    const ephemeral = crypto.createPrivateKey(generator.EPHEMERAL_PRIVATE_KEY_PEM);
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

    expect(kek.toString('hex')).toBe(VECTORS.expected.kekHex);
    expect(kek.equals(ceremonyKey)).toBe(false);
});

test('every element of the binding is load-bearing', () => {
    const sealed = seal();
    const tampered = {
        keyId: '00000000-0000-4000-8000-000000000000',
        oldKeyId: '00000000-0000-4000-8000-000000000001',
        algorithm: 'eddsa',
        importerIndex: 4,
        newThreshold: 4,
        oldThreshold: 3,
        publicKey: `04${'11'.repeat(64)}`,
        chainCode: '22'.repeat(32),
    };

    expect(open(sealed).toString('hex')).toBe(VECTORS.input.pointHex);

    for (const [field, value] of Object.entries(tampered)) {
        const binding = {...VECTORS.input.binding, [field]: value};

        expect(() => open(sealed, {binding: binding}), `${field} is not bound`).toThrow();
    }
});

test('a replay into another ceremony fails', () => {
    const sealed = seal();
    const otherSession = Buffer.from('00000000000000000000000000000000', 'hex');

    expect(() => open(sealed, {sessionId: otherSession})).toThrow();
});

test('an envelope addressed to one node cannot be opened by another', () => {
    const otherNode = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
    const sealed = seal();

    expect(() => open(sealed, {recipientPrivateKey: otherNode.privateKey})).toThrow();
});

test('two seals of the same point differ, so nothing is deterministic on the wire', () => {
    const first = seal();
    const second = seal();

    expect(first.senderPublicKey).not.toBe(second.senderPublicKey);
    expect(first.payload).not.toBe(second.payload);
    expect(open(first).toString('hex')).toBe(VECTORS.input.pointHex);
    expect(open(second).toString('hex')).toBe(VECTORS.input.pointHex);
});

test('the binding is length-prefixed, so adjacent fields cannot be slid into each other', () => {
    const base = VECTORS.input.binding;
    // "3" || "32" vs "33" || "2": identical if the elements are simply concatenated.
    const left = envelope.computeBinding({...base, importerIndex: 3, newThreshold: 32});
    const right = envelope.computeBinding({...base, importerIndex: 33, newThreshold: 2});

    expect(left.equals(right)).toBe(false);
    expect(envelope.computeBinding(base).toString('hex')).toBe(VECTORS.expected.bindingDigestHex);
});

test('malformed inputs are refused instead of sealed', () => {
    expect(() => seal({point: '00'.repeat(31)})).toThrow('point must be exactly 32 bytes');
    expect(() => seal({nonce: '00'.repeat(11)})).toThrow('nonce must be exactly 12 bytes');
    expect(() => seal({sessionId: Buffer.alloc(0)})).toThrow('sessionId must not be empty');
    expect(() => seal({binding: {...VECTORS.input.binding, algorithm: 'schnorr'}}))
        .toThrow('binding.algorithm must be one of');
    expect(() => seal({binding: {...VECTORS.input.binding, importerIndex: -1}}))
        .toThrow('binding.importerIndex must be a non-negative integer');
    expect(() => seal({binding: {...VECTORS.input.binding, keyId: ''}}))
        .toThrow('binding.keyId must be a non-empty string');

    // An RSA recipient key is the shape someone would reach for out of habit; mpc-node's
    // identity key is EC P-256 and nothing else.
    const rsa = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    expect(() => seal({recipientPublicKey: rsa.publicKey})).toThrow('must be an EC public key');

    const p384 = crypto.generateKeyPairSync('ec', {namedCurve: 'secp384r1'});
    expect(() => seal({recipientPublicKey: p384.publicKey})).toThrow('must be on prime256v1');
});
