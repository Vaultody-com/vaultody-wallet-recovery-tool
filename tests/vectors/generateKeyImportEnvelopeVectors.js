'use strict';

/**
 * Regenerates tests/vectors/key-import-envelope-v1.json.
 *
 *     node tests/vectors/generateKeyImportEnvelopeVectors.js
 *
 * Every input below is FIXED and checked in, so the file is reproducible byte for byte and the
 * Go side (mpc-node / mpc-node-api) can be tested against exactly these bytes without running
 * the tool. Nothing here is real key material — the keypairs were generated for this file and
 * are used nowhere else.
 *
 * FOUR cases, because two axes change what the binding contains and neither may be left to a
 * reader's imagination:
 *
 *   kind        recovery pins oldKeyId, the retired public key and a real oldThreshold;
 *               migration has no retired key at all, so those three are empty / empty / 0.
 *   algorithm   the retired public key is a COMPRESSED point, and the two curves compress
 *               differently — 33 bytes for secp256k1 (02/03 parity byte || X), 32 for ed25519.
 *
 * The retired public keys are not literals: they are derived here through
 * src/lib/utils/curve.js encodePoint, the same function the tool uses, so the vectors pin the
 * encoder rather than a hand-typed constant. Their scalars/seeds are published so Go can rebuild
 * them.
 *
 * The intermediates (sharedSecret, kek, bindingDigest) are published on purpose: when the Go
 * implementation disagrees on the final payload, they say WHICH step diverged.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const BN = require('bn.js');
const {ec: ECDSA, eddsa: EDDSA} = require('elliptic');

const envelope = require('../../src/lib/utils/keyImportEnvelope');
const curveUtils = require('../../src/lib/utils/curve');
const {CURVE} = require('../../src/lib/enumerations/curve');

const OUTPUT_FILE = path.join(__dirname, 'key-import-envelope-v1.json');

const secp256k1 = new ECDSA(CURVE.SECP256K1);
const ed25519 = new EDDSA(CURVE.ED25519);

// The recipient node's long-term identity key — one node, four sealed parts. mpc-node holds the
// private half as base64 of the SEC1 DER (config.PrivateKey -> x509.ParseECPrivateKey) and
// publishes the public half as base64 of the PKIX DER (config.DerivePublicKey).
const RECIPIENT_PRIVATE_KEY_PEM = [
    '-----BEGIN EC PRIVATE KEY-----',
    'MHcCAQEEIG+90ZhpoZOZBQ3dHC5XlraqHRiiQAmRxNAiTfiUzd8roAoGCCqGSM49',
    'AwEHoUQDQgAEhzFzO91z1Jg81jEUMOKQ6gfeME5QToaM99a0fZKyqE5bwc4nK/Cg',
    'nGv1PM/dhMIgSctAUgR5w0wODFwHW2AE6Q==',
    '-----END EC PRIVATE KEY-----',
].join('\n');

// One ephemeral key per part, as in production, where it is generated inside sealPoint and the
// private half is dropped. Pinned here only so the vectors are deterministic. Each case also
// gets its own sessionId and nonce, so no two cases ever reuse a (KEK, nonce) pair.
const CASES = [
    {
        name: 'recovery-ecdsa',
        description: 'A retired secp256k1 key restored into a new 3-of-n, sealed to the '
            + 'co-signer at index 3. The retired public key is the 33-byte compressed point.',
        ephemeralPrivateKeyPem: [
            '-----BEGIN EC PRIVATE KEY-----',
            'MHcCAQEEIPM+oqKQcfGWJt6aTwGy/A17hRZoQKlqSATY+c+z+yFwoAoGCCqGSM49',
            'AwEHoUQDQgAE99QzvR/94l74Lp37bHqCWFUFJtJf+0QZJhBQTk6j5XwkeYrLhpHC',
            '3Y2fup8+LVMxn9ucCy3K/kkCzzNU6RrOQQ==',
            '-----END EC PRIVATE KEY-----',
        ].join('\n'),
        sessionIdHex: '50a1eb702f96abc9c370319c82edce98',
        nonceHex: '9b95e36937584044f008ee7f',
        pointHex: 'b34509328c2f5b17598dec81a2ab8241df4789109cf91d0a4db21995f7ae2810',
        retiredKeyScalarHex: '104d1f7e53f00aac4eec8dc02994c5eee0002bff3375c669c541286386e14cad',
        binding: {
            kind: 'recovery',
            keyId: '6617a201-18d7-45e3-822c-17e725ea2387',
            oldKeyId: '25557f71-7375-4671-b218-d6cd7ebfc94e',
            algorithm: 'ecdsa',
            importerIndex: 3,
            newThreshold: 3,
            oldThreshold: 2,
            chainCode: 'e35363d87e86afddae08a99aa142a836a5e0af8c4c24a41db67ca9c15389fb71',
        },
    },
    {
        name: 'recovery-eddsa',
        description: 'A retired ed25519 key, whose encoded point is 32 bytes and not 33, '
            + 'restored into a 5-of-n and sealed to the mobile approver at index 2. '
            + 'oldThreshold is 1: a retired 1-of-n key is a legitimate thing to restore.',
        ephemeralPrivateKeyPem: [
            '-----BEGIN EC PRIVATE KEY-----',
            'MHcCAQEEIHavviP2NN9EAnZbzvVb4SXj3LOVBmEUT23EofT7NP7ZoAoGCCqGSM49',
            'AwEHoUQDQgAEGtxJI3XvriQCQMgbGA937vwdsdtKv9LY+taAB8ukLe2F3iMBulKa',
            'qJorlH2LgC/uf/GyPW8vM4AFb/Rd0BUOcg==',
            '-----END EC PRIVATE KEY-----',
        ].join('\n'),
        sessionIdHex: 'f606720e2ed32001bd507e22a18f53ee',
        nonceHex: '34f2cf81bbf06d392dba8796',
        pointHex: 'f51b2efa073d41a53ab6709916326d5c3146b1af01b499635b8cd0cc27365eac',
        retiredKeySeedHex: '1c37152f01d4a6d001a5984e5700161a6e3a40a89e384236799ad5877e05c4d7',
        binding: {
            kind: 'recovery',
            keyId: '35b9d6af-d9e0-47be-affc-e86696eed176',
            oldKeyId: '9cd54393-0642-42a7-b41c-25b57913b16f',
            algorithm: 'eddsa',
            importerIndex: 2,
            newThreshold: 5,
            oldThreshold: 1,
            chainCode: '775d6eb04d003bf1d6d9307a921632b945d192721f8ae9a273a650436e3734a2',
        },
    },
    {
        name: 'migration-ecdsa',
        description: 'No retired key exists, so there is no anchor and none is required: '
            + 'oldKeyId is empty, publicKey is empty, oldThreshold is 0. The chain code is the '
            + 'supplied one. Sealed to a Vaultody node at index 0.',
        ephemeralPrivateKeyPem: [
            '-----BEGIN EC PRIVATE KEY-----',
            'MHcCAQEEIHqq1jSN2Se3MXC3H2F2TMLvkSKL9sMVk8J2PpzLmGjuoAoGCCqGSM49',
            'AwEHoUQDQgAEAhN3S9F9yOTLAXOdUXppD0TbIh+CDW5YKCorpQkjLHNv0I7y4WeY',
            'ydTUYozcKrnPPcvosOvin+Q/PqM7qqpJ8Q==',
            '-----END EC PRIVATE KEY-----',
        ].join('\n'),
        sessionIdHex: 'dc8324c4e2bab2e934f0b8485d4efa9e',
        nonceHex: 'b67637d6b238ca3c66b982b0',
        pointHex: '2597947b7fdd3bc44c328c8035f70321642bb3ac0d04fdb6d332a7614b434b8d',
        binding: {
            kind: 'migration',
            keyId: '3247b41b-fb9f-4bb7-93bf-4b2eae5f2696',
            oldKeyId: '',
            algorithm: 'ecdsa',
            importerIndex: 0,
            newThreshold: 3,
            oldThreshold: 0,
            publicKey: '',
            chainCode: 'f0a31a85e1719f3e19c7f00cbfcbc8ff40153bdc388fb01e95b40559d5b6213b',
        },
    },
    {
        name: 'migration-eddsa',
        description: 'The same empty-anchor shape on the other curve, sealed to a Vaultody node '
            + 'at index 1. Nothing about the empty elements depends on the algorithm — this case '
            + 'exists so an implementation cannot pass by special-casing one curve.',
        ephemeralPrivateKeyPem: [
            '-----BEGIN EC PRIVATE KEY-----',
            'MHcCAQEEIAJrxlB3pkrrYCVrHZYkmG8WP3hiHR2i4YdNPLQ44ugmoAoGCCqGSM49',
            'AwEHoUQDQgAEzGItkZqVLByugxbW6U3y1MemCLkC214lP9GRpfRn9JO/D8jPQL7P',
            'RZUiCYvjqW1qhBgK1+Hg/hb+D4G3QMkIcQ==',
            '-----END EC PRIVATE KEY-----',
        ].join('\n'),
        sessionIdHex: 'b18edf3dc593474144b9e9657c0e1e33',
        nonceHex: 'e3f96a085af237312cbcf9fa',
        pointHex: '8fc7e34f2b52550248ef1431053d66c0243021c09f1f95cd514fcb2521545955',
        binding: {
            kind: 'migration',
            keyId: '911a2310-eb9a-41ad-8c43-9555a60e9c69',
            oldKeyId: '',
            algorithm: 'eddsa',
            importerIndex: 1,
            newThreshold: 2,
            oldThreshold: 0,
            publicKey: '',
            chainCode: 'c43c2c01bd143b6c433e398c067d0f953d829e7b0c86c73ffd7995077d75d046',
        },
    },
];

/**
 * @param {crypto.KeyObject} privateKey
 * @return {{privateKeyPem: string, privateKeySec1Base64: string, publicKeyPkixBase64: string}}
 */
function describeKeyPair(privateKey) {
    const publicKey = crypto.createPublicKey(privateKey);

    return {
        privateKeyPem: privateKey.export({type: 'sec1', format: 'pem'}).toString().trim(),
        privateKeySec1Base64: privateKey.export({type: 'sec1', format: 'der'}).toString('base64'),
        publicKeyPkixBase64: publicKey.export({type: 'spki', format: 'der'}).toString('base64'),
    };
}

/**
 * Derives the retired group public key in the COMPRESSED form the binding takes, through the same
 * encoder the tool uses. Returns null for a migration case, which has no retired key.
 *
 * @param {object} testCase
 * @return {?{curve: string, derivation: string, secretHex: string, encodedHex: string}}
 */
function deriveRetiredPublicKey(testCase) {
    if (testCase.retiredKeyScalarHex !== undefined) {
        const point = secp256k1.g.mul(new BN(testCase.retiredKeyScalarHex, 16));

        return {
            curve: CURVE.SECP256K1,
            derivation: 'encodePoint(secp256k1, secretHex * G) — SEC1 compressed, 33 bytes',
            secretHex: testCase.retiredKeyScalarHex,
            encodedHex: curveUtils.encodePoint(CURVE.SECP256K1, point).toString('hex'),
        };
    }
    if (testCase.retiredKeySeedHex !== undefined) {
        const point = ed25519.keyFromSecret(testCase.retiredKeySeedHex).pub();

        return {
            curve: CURVE.ED25519,
            derivation: 'encodePoint(ed25519, public point of the keypair with this seed) — 32 bytes',
            secretHex: testCase.retiredKeySeedHex,
            encodedHex: curveUtils.encodePoint(CURVE.ED25519, point).toString('hex'),
        };
    }

    return null;
}

/**
 * @param {crypto.KeyObject} recipientPrivateKey
 * @param {object} recipient
 * @param {object} testCase
 * @return {object}
 */
function buildCase(recipientPrivateKey, recipient, testCase) {
    const ephemeralPrivateKey = crypto.createPrivateKey(testCase.ephemeralPrivateKeyPem);
    const ephemeral = describeKeyPair(ephemeralPrivateKey);
    const sessionId = Buffer.from(testCase.sessionIdHex, 'hex');
    const retiredKey = deriveRetiredPublicKey(testCase);

    const binding = retiredKey === null
        ? testCase.binding
        : {...testCase.binding, publicKey: retiredKey.encodedHex};

    const sealed = envelope.sealPoint({
        point: testCase.pointHex,
        recipientPublicKey: recipient.publicKeyPkixBase64,
        sessionId: sessionId,
        binding: binding,
        ephemeralPrivateKey: ephemeralPrivateKey,
        nonce: testCase.nonceHex,
    });

    const {sharedSecret, kek} = envelope.deriveKek(
        ephemeralPrivateKey,
        crypto.createPublicKey(recipientPrivateKey),
        sessionId
    );

    return {
        name: testCase.name,
        description: testCase.description,
        input: {
            ephemeral: ephemeral,
            sessionIdHex: testCase.sessionIdHex,
            nonceHex: testCase.nonceHex,
            pointHex: testCase.pointHex,
            retiredKey: retiredKey,
            binding: binding,
        },
        expected: {
            sharedSecretHex: sharedSecret.toString('hex'),
            kekHex: kek.toString('hex'),
            bindingDigestHex: sealed.bindingDigest.toString('hex'),
            ciphertextHex: sealed.ciphertext.toString('hex'),
            authTagHex: sealed.authTag.toString('hex'),
            senderPublicKey: sealed.senderPublicKey,
            payload: sealed.payload,
        },
    };
}

/**
 * @return {object}
 */
function buildVectors() {
    const recipientPrivateKey = crypto.createPrivateKey(RECIPIENT_PRIVATE_KEY_PEM);
    const recipient = describeKeyPair(recipientPrivateKey);

    return {
        description: 'Fixed ENVELOPE v1 test vectors for the MPC key-import share sealing. '
            + 'Generated by tests/vectors/generateKeyImportEnvelopeVectors.js. No real key '
            + 'material — the keypairs exist only for this file.',
        version: envelope.ENVELOPE_LABEL,
        kekInfoLabel: envelope.KEK_INFO_LABEL,
        curve: 'prime256v1',
        kdf: 'HKDF-SHA256(ikm = ECDH shared X, salt = nil, info = kekInfoLabel || hex(sessionId), len = 32)',
        aead: 'AES-256-GCM, aad = SHA-256 of the length-prefixed canonical binding',
        wireForm: 'senderPublicKey = base64(PKIX DER of the ephemeral public key); '
            + 'payload = base64(nonce || ciphertext || tag)',
        bindingElementOrder: [
            'label ("' + envelope.ENVELOPE_LABEL + '", ASCII)',
            'kind (ASCII, "recovery" | "migration")',
            'keyId (ASCII uuid, the NEW key)',
            'oldKeyId (ASCII uuid, the retired key; empty string when kind = migration)',
            'algorithm (ASCII, "ecdsa" | "eddsa"; pinned by the node)',
            'importerIndex (decimal ASCII; pinned by the node)',
            'newThreshold (decimal ASCII)',
            'oldThreshold (decimal ASCII; 0 when kind = migration)',
            'publicKey (RAW COMPRESSED bytes of the retired group public key; empty when kind = migration)',
            'chainCode (raw bytes of the chain code: the retired one on recovery, the supplied one on migration)',
        ],
        bindingElementPrefix: 'each element is preceded by its byte length as a 4-byte big-endian uint32',
        retiredPublicKeyEncoding: 'Point.Encode(): SEC1 COMPRESSED for secp256k1 — '
            + `${envelope.RETIRED_PUBLIC_KEY_BYTES_LENGTH.ecdsa} bytes, an 02/03 parity byte over `
            + `the 32-byte X — and ed25519's own `
            + `${envelope.RETIRED_PUBLIC_KEY_BYTES_LENGTH.eddsa}-byte encoded point. Never `
            + 'uncompressed: the api caps the field at 66 hex characters.',
        recipient: recipient,
        cases: CASES.map(testCase => buildCase(recipientPrivateKey, recipient, testCase)),
    };
}

if (require.main === module) {
    fs.writeFileSync(OUTPUT_FILE, `${JSON.stringify(buildVectors(), null, 4)}\n`);
    process.stdout.write(`wrote ${OUTPUT_FILE}\n`);
}

module.exports = {
    OUTPUT_FILE,
    RECIPIENT_PRIVATE_KEY_PEM,
    CASES,
    buildVectors,
};
