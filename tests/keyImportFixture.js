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
const curveUtils = require('../src/lib/utils/curve');
const nodeKeys = require('../src/lib/vaultodyNodePublicKeys');
const {CURVE, DOMAIN_PARAMS, PREFIXES} = require('../src/lib/enumerations/curve');

// A server_cosigner vault: the two Vaultody nodes and the client's own co-signer, whose index is
// 3 and not 2 — the case where a part's position in the array is not its coordinate.
const SEATS = [0, 1, 3];

// A mobile_cosigner vault: the two Vaultody nodes and the client's handset at seat 2.
const MOBILE_SEATS = [0, 1, nodeKeys.SEAT.MOBILE_DEVICE];
const OLD_THRESHOLD = 2;
const NEW_THRESHOLD = 3;
const KEY_ID = '6617a201-18d7-45e3-822c-17e725ea2387';
const OLD_KEY_ID = '25557f71-7375-4671-b218-d6cd7ebfc94e';
// A vault holding both algorithms runs two independent keys, each with its own id and its own
// import session — which is the whole reason one sealed file has to carry both.
const EDDSA_KEY_ID = 'b0c1f3d2-4a55-4c6e-9f10-2b3c4d5e6f70';
const EDDSA_OLD_KEY_ID = 'c9d8e7f6-1a2b-4c3d-8e9f-0a1b2c3d4e5f';
const VAULT_ID = '651f0b2d9c1f4a0e8f3d2c11';

const domainParams = DOMAIN_PARAMS[CURVE.SECP256K1];

const KEY_IDS = {
    [envelope.ALGORITHM.ECDSA]: {keyId: KEY_ID, oldKeyId: OLD_KEY_ID},
    [envelope.ALGORITHM.EDDSA]: {keyId: EDDSA_KEY_ID, oldKeyId: EDDSA_OLD_KEY_ID},
};

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
 * The curve is a parameter because a vault can hold an ecdsa AND an eddsa key, and the two are
 * separate sharings of separate secrets, backed up into separate files — the case the sealer has
 * to cover in ONE run. The seats are a parameter because a mobile_cosigner vault's package holds
 * a part for seat 2 where a server_cosigner one holds a part for seat 3.
 *
 * @param {object} overrides
 * @param {string} curve
 * @param {number[]} seats
 * @return {{data: object, secret: BN, shares: Map<number, BN>, chainCode: string,
 *           curve: string, algorithm: string, compressedPublicKey: string}}
 */
function buildBackupPackage(overrides = {}, curve = CURVE.SECP256K1, seats = SEATS) {
    const params = DOMAIN_PARAMS[curve];
    const secret = new BN(crypto.randomBytes(31));
    const coefficient = new BN(crypto.randomBytes(31));

    const shares = new Map();
    for (const seat of seats) {
        // f(x) = secret + coefficient*x, evaluated at the part's own coordinate, which is its
        // player index plus one.
        const x = new BN(seat + 1);
        shares.set(seat, secret.add(coefficient.mul(x)).mod(params.n));
    }

    const chainCode = crypto.randomBytes(32);
    const chainCodeKey = crypto.randomBytes(32);
    const cipher = crypto.createCipheriv('aes-256-gcm', chainCodeKey, Buffer.alloc(12, 0));
    const chainCodeCiphertext = Buffer.concat([
        cipher.update(Buffer.from(JSON.stringify({master_chain_code: chainCode.toString('base64')}))),
        cipher.final(),
    ]);

    const publicKeyPoint = params.g.mul(secret);
    // The SubjectPublicKeyInfo body a backup package carries: the UNCOMPRESSED SEC1 point on
    // secp256k1, and ed25519's own 32-byte encoded point.
    const publicKey = Buffer.concat([
        Buffer.from(PREFIXES[curve], 'hex'),
        curve === CURVE.SECP256K1
            ? Buffer.from(publicKeyPoint.encode('array', false))
            : curveUtils.encodePoint(curve, publicKeyPoint),
    ]);

    return {
        secret: secret,
        shares: shares,
        curve: curve,
        algorithm: curve === CURVE.SECP256K1 ? envelope.ALGORITHM.ECDSA : envelope.ALGORITHM.EDDSA,
        chainCode: chainCode.toString('hex'),
        // The same encoding the binding is defined over, which is what a migration ticket has
        // to declare: Point.Encode(), not the package's SubjectPublicKeyInfo.
        compressedPublicKey: curveUtils.encodePoint(curve, publicKeyPoint).toString('hex'),
        data: {
            public_key: publicKey.toString('base64'),
            version: '3',
            sharing_type: 'shamir',
            master_chain_code: Buffer.concat([chainCodeCiphertext, cipher.getAuthTag()]).toString('base64'),
            master_chain_code_key: crypto.publicEncrypt(
                {key: clientRsaKey.publicKey, oaepHash: 'sha256'},
                chainCodeKey
            ).toString('base64'),
            key_parts: seats.map(seat => ({index: seat, data: encryptShare(shares.get(seat))})),
            ...overrides,
        },
    };
}

/**
 * @return {{privateKey: object, publicKey: string}}
 */
function generateNodeKey() {
    const pair = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});

    return {
        privateKey: pair.privateKey,
        publicKey: pair.publicKey.export({type: 'spki', format: 'der'}).toString('base64'),
    };
}

// VAULTODY's own two nodes are a property of the DEPLOYMENT, not of a ticket: every ticket a
// client ever downloads names the same pair, which is exactly what makes them pinnable in a
// build. So they are generated once for the whole run and reused, while the client-held seats —
// a handset, a self-hosted co-signer — are generated per call, as they are per client.
const vaultodyNodeKeys = new Map();

/**
 * One P-256 identity key per seat, as every mpc-node has.
 *
 * @param {number[]} seats
 * @return {Map<number, {privateKey: object, publicKey: string}>}
 */
function buildNodeKeys(seats = SEATS) {
    const keys = new Map();
    for (const seat of seats) {
        if (!nodeKeys.isPinnedSeat(seat)) {
            keys.set(seat, generateNodeKey());
            continue;
        }

        if (!vaultodyNodeKeys.has(seat)) {
            vaultodyNodeKeys.set(seat, generateNodeKey());
        }

        keys.set(seat, vaultodyNodeKeys.get(seat));
    }

    return keys;
}

/**
 * The pinned table a build cut against THIS fixture's deployment would carry: VAULTODY's own two
 * node keys and nothing else. Every test that expects a seal to succeed constructs the service
 * with it, which is what a signed release build does with the real pair.
 *
 * @return {object} seat index -> base64 PKIX DER
 */
function pinnedNodePublicKeys() {
    const pinned = {};
    for (const seat of nodeKeys.PINNED_SEATS) {
        if (!vaultodyNodeKeys.has(seat)) {
            vaultodyNodeKeys.set(seat, generateNodeKey());
        }

        pinned[seat] = vaultodyNodeKeys.get(seat).publicKey;
    }

    return pinned;
}

/**
 * One algorithm's session on a ticket: every seat, its node's public key, and the session id the
 * envelope key for that algorithm is derived over. Each algorithm gets its OWN session id and
 * its own key ids.
 *
 * @param {Map<number, {publicKey: string}>} nodeKeys
 * @param {string} algorithm
 * @param {object} overrides
 * @return {object}
 */
function buildSession(nodeKeys, algorithm, overrides = {}) {
    const players = {};
    for (const [seat, key] of nodeKeys) {
        players[seat] = key.publicKey;
    }

    return {
        algorithm: algorithm,
        sessionId: crypto.randomBytes(32).toString('hex'),
        players: players,
        oldKeyId: KEY_IDS[algorithm].oldKeyId,
        keyId: KEY_IDS[algorithm].keyId,
        threshold: NEW_THRESHOLD,
        oldThreshold: OLD_THRESHOLD,
        ...overrides,
    };
}

/**
 * A single-algorithm (ecdsa) recovery ticket — a vault holding only a secp256k1 key.
 *
 * @param {Map<number, {publicKey: string}>} nodeKeys
 * @param {object} overrides applied to the session metadata
 * @param {object} ticketOverrides applied to the ticket itself
 * @return {object}
 */
function buildTicket(nodeKeys, overrides = {}, ticketOverrides = {}) {
    return {
        vaultId: VAULT_ID,
        kind: envelope.KIND.RECOVERY,
        keyImportMetadata: [buildSession(nodeKeys, envelope.ALGORITHM.ECDSA, overrides)],
        ...ticketOverrides,
    };
}

/**
 * The ticket of a vault holding BOTH keys: two sessions, which vaults-manager will walk one by
 * one and refuse the upload for if either is short a seat.
 *
 * @param {Map<number, {publicKey: string}>} nodeKeys
 * @param {object} ecdsaOverrides
 * @param {object} eddsaOverrides
 * @return {object}
 */
function buildTwoAlgorithmTicket(nodeKeys, ecdsaOverrides = {}, eddsaOverrides = {}) {
    return {
        vaultId: VAULT_ID,
        kind: envelope.KIND.RECOVERY,
        keyImportMetadata: [
            buildSession(nodeKeys, envelope.ALGORITHM.ECDSA, ecdsaOverrides),
            buildSession(nodeKeys, envelope.ALGORITHM.EDDSA, eddsaOverrides),
        ],
    };
}

/**
 * A migration ticket: no retired key anywhere on it, and instead the key being brought in,
 * declared when the import was initialized and echoed back here so the tool binds exactly what
 * the nodes will be handed.
 *
 * @param {Map<number, {publicKey: string}>} nodeKeys
 * @param {{chainCode: string, compressedPublicKey: string}} backup
 * @param {object} externalKeyOverrides
 * @return {object}
 */
function buildMigrationTicket(nodeKeys, backup, externalKeyOverrides = {}) {
    const ticket = buildTicket(nodeKeys, {oldKeyId: '', oldThreshold: 0});

    return {
        ...ticket,
        kind: envelope.KIND.MIGRATION,
        externalKeys: [
            {
                algorithm: envelope.ALGORITHM.ECDSA,
                chainCode: backup.chainCode,
                publicKey: backup.compressedPublicKey,
                ...externalKeyOverrides,
            },
        ],
    };
}

/**
 * A migration of a two-algorithm vault: one declared key per algorithm, each echoed back from
 * what was given when the import was initialized.
 *
 * @param {Map<number, {publicKey: string}>} nodeKeys
 * @param {{chainCode: string, compressedPublicKey: string}} ecdsaBackup
 * @param {{chainCode: string, compressedPublicKey: string}} eddsaBackup
 * @return {object}
 */
function buildTwoAlgorithmMigrationTicket(nodeKeys, ecdsaBackup, eddsaBackup) {
    const retired = {oldKeyId: '', oldThreshold: 0};
    const ticket = buildTwoAlgorithmTicket(nodeKeys, retired, retired);

    return {
        ...ticket,
        kind: envelope.KIND.MIGRATION,
        externalKeys: [
            {
                algorithm: envelope.ALGORITHM.ECDSA,
                chainCode: ecdsaBackup.chainCode,
                publicKey: ecdsaBackup.compressedPublicKey,
            },
            {
                algorithm: envelope.ALGORITHM.EDDSA,
                chainCode: eddsaBackup.chainCode,
                publicKey: eddsaBackup.compressedPublicKey,
            },
        ],
    };
}

module.exports = {
    SEATS,
    MOBILE_SEATS,
    OLD_THRESHOLD,
    NEW_THRESHOLD,
    KEY_ID,
    OLD_KEY_ID,
    EDDSA_KEY_ID,
    EDDSA_OLD_KEY_ID,
    VAULT_ID,
    domainParams,
    clientRsaKey,
    toPaddedHex,
    buildBackupPackage,
    buildNodeKeys,
    generateNodeKey,
    pinnedNodePublicKeys,
    buildSession,
    buildTicket,
    buildTwoAlgorithmTicket,
    buildMigrationTicket,
    buildTwoAlgorithmMigrationTicket,
};
