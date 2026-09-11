'use strict';

/**
 * Builds a VAULTODY backup package that holds a REAL 2-of-3 Shamir sharing, the matching
 * key-import ticket, and one P-256 identity key per seat — everything the sealing path needs,
 * without a node and without any checked-in key material.
 */

const crypto = require('crypto');
const BN = require('bn.js');
const bip39 = require('bip39');

const envelope = require('../src/lib/utils/keyImportEnvelope');
const {CURVE, DOMAIN_PARAMS, PREFIXES} = require('../src/lib/enumerations/curve');

// The seats of a vault whose mobile player was replaced: two Vaultody nodes and a server
// co-signer, whose index is 3 and not 2 — the case where a part's position in the array is not
// its coordinate.
const SEATS = [0, 1, 3];
const OLD_THRESHOLD = 2;
const NEW_THRESHOLD = 3;
const KEY_ID = '6617a201-18d7-45e3-822c-17e725ea2387';
const OLD_KEY_ID = '25557f71-7375-4671-b218-d6cd7ebfc94e';
const VAULT_ID = '651f0b2d9c1f4a0e8f3d2c11';

const domainParams = DOMAIN_PARAMS[CURVE.SECP256K1];

// 3072 bits, not 2048: a 24-word mnemonic is up to ~190 bytes and OAEP-SHA256 leaves a 2048-bit
// key only 190, which is exactly the edge. The fixture must not be flaky.
const clientRsaKey = crypto.generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicKeyEncoding: {type: 'pkcs1', format: 'pem'},
    privateKeyEncoding: {type: 'pkcs1', format: 'pem'},
});

/**
 * @param {BN} value
 * @return {string}
 */
function toPaddedHex(value) {
    return value.toString('hex', 64);
}

/**
 * Encrypts one key part the way a VAULTODY backup package does: the share as a BIP39 mnemonic,
 * RSA-OAEP-SHA256 to the client's own public key.
 *
 * @param {BN} share
 * @return {string}
 */
function encryptShare(share) {
    const mnemonic = bip39.entropyToMnemonic(toPaddedHex(share));

    return crypto.publicEncrypt(
        {key: clientRsaKey.publicKey, oaepHash: 'sha256'},
        Buffer.from(mnemonic)
    ).toString('base64');
}

/**
 * Builds a version 3 backup package holding a real 2-of-3 Shamir sharing, so what the service
 * seals can be interpolated back to the secret it started from.
 *
 * @param {object} overrides
 * @return {{data: object, secret: BN, shares: Map<number, BN>, chainCode: string}}
 */
function buildBackupPackage(overrides = {}) {
    const secret = new BN(crypto.randomBytes(31));
    const coefficient = new BN(crypto.randomBytes(31));

    const shares = new Map();
    for (const seat of SEATS) {
        // f(x) = secret + coefficient*x, evaluated at the part's own coordinate, which is its
        // player index plus one.
        const x = new BN(seat + 1);
        shares.set(seat, secret.add(coefficient.mul(x)).mod(domainParams.n));
    }

    const chainCode = crypto.randomBytes(32);
    const chainCodeKey = crypto.randomBytes(32);
    const cipher = crypto.createCipheriv('aes-256-gcm', chainCodeKey, Buffer.alloc(12, 0));
    const chainCodeCiphertext = Buffer.concat([
        cipher.update(Buffer.from(JSON.stringify({master_chain_code: chainCode.toString('base64')}))),
        cipher.final(),
    ]);

    const publicKeyPoint = domainParams.g.mul(secret);
    const publicKey = Buffer.concat([
        Buffer.from(PREFIXES[CURVE.SECP256K1], 'hex'),
        Buffer.from(publicKeyPoint.encode('array', false)),
    ]);

    return {
        secret: secret,
        shares: shares,
        chainCode: chainCode.toString('hex'),
        data: {
            public_key: publicKey.toString('base64'),
            version: '3',
            sharing_type: 'shamir',
            master_chain_code: Buffer.concat([chainCodeCiphertext, cipher.getAuthTag()]).toString('base64'),
            master_chain_code_key: crypto.publicEncrypt(
                {key: clientRsaKey.publicKey, oaepHash: 'sha256'},
                chainCodeKey
            ).toString('base64'),
            key_parts: SEATS.map(seat => ({index: seat, data: encryptShare(shares.get(seat))})),
            ...overrides,
        },
    };
}

/**
 * One P-256 identity key per seat, as every mpc-node has.
 *
 * @return {Map<number, {privateKey: object, publicKey: string}>}
 */
function buildNodeKeys() {
    const nodeKeys = new Map();
    for (const seat of SEATS) {
        const pair = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
        nodeKeys.set(seat, {
            privateKey: pair.privateKey,
            publicKey: pair.publicKey.export({type: 'spki', format: 'der'}).toString('base64'),
        });
    }

    return nodeKeys;
}

/**
 * @param {Map<number, {publicKey: string}>} nodeKeys
 * @param {object} overrides
 * @return {object}
 */
function buildTicket(nodeKeys, overrides = {}) {
    const players = {};
    for (const [seat, key] of nodeKeys) {
        players[seat] = key.publicKey;
    }

    return {
        vaultId: VAULT_ID,
        kind: envelope.KIND.RECOVERY,
        keyImportMetadata: [
            {
                algorithm: envelope.ALGORITHM.ECDSA,
                sessionId: crypto.randomBytes(32).toString('hex'),
                players: players,
                oldKeyId: OLD_KEY_ID,
                keyId: KEY_ID,
                threshold: NEW_THRESHOLD,
                oldThreshold: OLD_THRESHOLD,
                ...overrides,
            },
        ],
    };
}

module.exports = {
    SEATS,
    OLD_THRESHOLD,
    NEW_THRESHOLD,
    KEY_ID,
    OLD_KEY_ID,
    VAULT_ID,
    domainParams,
    clientRsaKey,
    toPaddedHex,
    buildBackupPackage,
    buildNodeKeys,
    buildTicket,
};
