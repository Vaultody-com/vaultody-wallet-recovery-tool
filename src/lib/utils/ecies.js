'use strict';

const crypto = require('crypto');
const bip39 = require('bip39');
const BN = require('bn.js');
const {curves} = require('elliptic');
const PACKAGE = require('../enumerations/backupPackage');

// The P-256 side of the ecies-p256-v1 format: the recovery key the 24 words
// derive, and the envelope every sealed part is opened from. Written with
// node:crypto only, the way Vaultody's Go nodes write it, so the test vectors
// in tests/backup-package.spec.js are a real check that the two agree.

const P256_ORDER = curves.p256.n;
const ECDH_CURVE = 'prime256v1';

/** The words are not a recovery phrase for this format, or do not fit this package. */
class RecoveryWordsError extends Error {}

/** A sealed part that is malformed, moved, tampered with, or sealed toward another key. */
class SealedPartError extends Error {}

/**
 * What a person typed, as the words: case and surrounding whitespace do not count.
 *
 * @param {string} text
 * @return {string[]}
 */
function normaliseWords(text) {
    return String(text || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
}

/**
 * 24 words, every one in the English list, checksum correct.
 *
 * @param {string[]} words
 * @return {boolean}
 */
function validRecoveryWords(words) {
    return Array.isArray(words) && words.length === PACKAGE.WORD_COUNT && bip39.validateMnemonic(words.join(' '));
}

/**
 * Is this hex a usable uncompressed P-256 point: the right shape AND on the curve?
 *
 * @param {string} hex
 * @return {boolean}
 */
function validRecipient(hex) {
    if (typeof hex !== 'string' || !PACKAGE.RECIPIENT_PATTERN.test(hex)) {
        return false;
    }

    try {
        const point = Buffer.from(hex, 'hex');
        crypto.createPublicKey({
            key: {
                kty: 'EC',
                crv: 'P-256',
                x: point.subarray(1, 33).toString('base64url'),
                y: point.subarray(33, 65).toString('base64url'),
            },
            format: 'jwk',
        });

        return true;
    } catch (e) {
        return false;
    }
}

/**
 * words -> entropy -> d = HKDF-SHA256(entropy, "", "vaultody:backup:v1") mod n, Q = d*G.
 * Deterministic: the same words always give the same key, which is what lets
 * this tool arrive at the key the wallet host sealed toward. The entropy goes
 * through HKDF and never through BIP39's seed derivation, so the words cannot
 * be mistaken for a wallet seed.
 *
 * @param {string[]} words
 * @return {{d: Buffer, Q: Buffer, publicKeyHex: string}} d is 32 bytes big-endian, Q 65 bytes uncompressed
 */
function recoveryKeyFromWords(words) {
    if (!validRecoveryWords(words)) {
        throw new RecoveryWordsError(
            `Those are not ${PACKAGE.WORD_COUNT} valid recovery words. Check the spelling and the order.`
        );
    }

    const entropy = Buffer.from(bip39.mnemonicToEntropy(words.join(' ')), 'hex');
    const okm = Buffer.from(crypto.hkdfSync('sha256', entropy, Buffer.alloc(0), PACKAGE.KEY_INFO, 32));
    entropy.fill(0);

    const d = new BN(okm).mod(P256_ORDER);
    okm.fill(0);

    // Never in practice; there is no retry, because the wallet host made no retry either.
    if (d.isZero()) {
        throw new RecoveryWordsError('These words derive an unusable recovery key.');
    }

    const scalar = d.toArrayLike(Buffer, 'be', 32);
    const ecdh = crypto.createECDH(ECDH_CURVE);
    ecdh.setPrivateKey(scalar);
    const Q = ecdh.getPublicKey(null, 'uncompressed');

    return {d: scalar, Q: Q, publicKeyHex: Q.toString('hex')};
}

/**
 * "keyId|index|algorithm|ecies-p256-v1": what binds a ciphertext to its place in the package.
 *
 * @param {{keyId: string, index: number, algorithm: string}} label
 * @return {Buffer}
 */
function additionalData(label) {
    return Buffer.from(`${label.keyId}|${label.index}|${label.algorithm}|${PACKAGE.VERSION}`, 'utf8');
}

/**
 * K = HKDF-SHA256(ikm = S, salt = "", info = version || Q || E, 32).
 *
 * @param {Buffer} shared
 * @param {Buffer} Q
 * @param {Buffer} E
 * @return {Buffer}
 */
function sharedKey(shared, Q, E) {
    const info = Buffer.concat([Buffer.from(PACKAGE.VERSION, 'utf8'), Q, E]);

    return Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.alloc(0), info, 32));
}

/**
 * Open one sealed part with the recovery key. The label the part carries is
 * bound into its ciphertext, so a part moved to another key, index or curve
 * does not open, and neither does one sealed toward another set of words.
 *
 * @param {Buffer} d the recovery scalar, 32 bytes
 * @param {Buffer} Q the recovery public key the package names, 65 bytes
 * @param {{keyId: string, index: number, algorithm: string, ephemeralPublicKey: string, nonce: string, ciphertext: string}} part
 * @return {Buffer} the plaintext
 */
function openPart(d, Q, part) {
    const place = `${part.keyId} (share ${part.index}, ${part.algorithm})`;

    if (!validRecipient(part.ephemeralPublicKey)) {
        throw new SealedPartError(`Sealed part ${place} carries an invalid ephemeral key.`);
    }

    const nonce = Buffer.from(String(part.nonce), 'base64');
    if (nonce.length !== PACKAGE.NONCE_BYTES) {
        throw new SealedPartError(`Sealed part ${place} carries an invalid nonce.`);
    }

    const sealed = Buffer.from(String(part.ciphertext), 'base64');
    if (sealed.length < PACKAGE.TAG_BYTES) {
        throw new SealedPartError(`Sealed part ${place} carries an invalid ciphertext.`);
    }

    const E = Buffer.from(part.ephemeralPublicKey, 'hex');
    const ecdh = crypto.createECDH(ECDH_CURVE);
    ecdh.setPrivateKey(d);
    const key = sharedKey(ecdh.computeSecret(E), Q, E);

    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
        decipher.setAAD(additionalData({keyId: part.keyId, index: part.index, algorithm: part.algorithm}));
        decipher.setAuthTag(sealed.subarray(sealed.length - PACKAGE.TAG_BYTES));

        return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - PACKAGE.TAG_BYTES)), decipher.final()]);
    } catch (e) {
        throw new SealedPartError(
            `Sealed part ${place} does not open with these words at this place in the package: ` +
            'it was sealed toward other words, moved, or altered.'
        );
    } finally {
        key.fill(0);
    }
}

/**
 * Seal one part toward Q: a fresh ephemeral key and nonce per part. This is
 * what the wallet host and the nodes do when a backup is made; the tool only
 * opens parts, and carries this for its own tests and example data.
 *
 * @param {string} recipientPublicKeyHex Q, uncompressed, lowercase hex
 * @param {{keyId: string, index: number, algorithm: string}} label
 * @param {Buffer} plaintext
 * @param {{ephemeral?: Buffer, nonce?: Buffer}} fixed for test vectors only
 * @return {{keyId: string, index: number, algorithm: string, ephemeralPublicKey: string, nonce: string, ciphertext: string}}
 */
function sealPart(recipientPublicKeyHex, label, plaintext, fixed = {}) {
    if (!validRecipient(recipientPublicKeyHex)) {
        throw new SealedPartError('The recipient is not an uncompressed P-256 public key.');
    }

    const Q = Buffer.from(recipientPublicKeyHex, 'hex');
    const ecdh = crypto.createECDH(ECDH_CURVE);
    if (fixed.ephemeral) {
        ecdh.setPrivateKey(fixed.ephemeral);
    } else {
        ecdh.generateKeys();
    }

    const E = ecdh.getPublicKey(null, 'uncompressed');
    const key = sharedKey(ecdh.computeSecret(Q), Q, E);
    const nonce = fixed.nonce || crypto.randomBytes(PACKAGE.NONCE_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(additionalData(label));
    const sealed = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    key.fill(0);

    return {
        keyId: label.keyId,
        index: label.index,
        algorithm: label.algorithm,
        ephemeralPublicKey: E.toString('hex'),
        nonce: nonce.toString('base64'),
        ciphertext: sealed.toString('base64'),
    };
}

module.exports = {
    RecoveryWordsError: RecoveryWordsError,
    SealedPartError: SealedPartError,
    normaliseWords: normaliseWords,
    validRecoveryWords: validRecoveryWords,
    validRecipient: validRecipient,
    recoveryKeyFromWords: recoveryKeyFromWords,
    openPart: openPart,
    sealPart: sealPart,
};
