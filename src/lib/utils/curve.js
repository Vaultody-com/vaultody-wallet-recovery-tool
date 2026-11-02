'use strict';

const { CURVE, PREFIXES } = require("../enumerations/curve");
const { ec: ECDSA, eddsa: EDDSA } = require("elliptic");
const BN = require("bn.js");
const ecdsa = new ECDSA(CURVE.SECP256K1);
const eddsa = new EDDSA(CURVE.ED25519);

/**
 * @param {string} curve
 * @param {Buffer} encodedPoint
 * @returns {BasePoint}
 */
function decodePoint(curve, encodedPoint) {
    switch (curve) {
        case CURVE.SECP256K1:
            return ecdsa.curve.decodePoint(encodedPoint);
        case CURVE.ED25519:
            return eddsa.decodePoint(encodedPoint.toString('hex'));
        default:
            throw new Error("Unknown curve");
    }
}

/**
 * @param {string} curve
 * @param {Point} point
 * @return {Buffer}
 */
function encodePoint(curve, point) {
    switch (curve) {
        case CURVE.SECP256K1:
            return ecdsa.curve.encodePoint(point);
        case CURVE.ED25519:
            return Buffer.from(eddsa.encodePoint(point));
        default:
            throw new Error("Unknown curve");
    }
}

/**
 * @param {Buffer} publicKey
 * @returns {string}
 */
function extractCurveFromPublicKey(publicKey) {
    return Object.keys(PREFIXES).find(curve => publicKey.toString("hex").includes(PREFIXES[curve]));
}

/**
 * The raw public key (the encoded point) inside a backup's public_key. The backup writes it as
 * base64(SPKI header) followed by base64(raw key): two base64 strings joined, which is not one valid
 * base64 string for secp256k1, whose 23-byte header ends in padding. So the header is cut off as text
 * first; a public_key stored as one clean SPKI base64 is handled too.
 *
 * @param {string} curve
 * @param {string} publicKeyBase64 the backup's public_key
 * @returns {Buffer}
 */
function rawPublicKeyFromBackup(curve, publicKeyBase64) {
    const header = Buffer.from(PREFIXES[curve], 'hex');
    const headerBase64 = header.toString('base64');
    if (publicKeyBase64.startsWith(headerBase64)) {
        return Buffer.from(publicKeyBase64.slice(headerBase64.length), 'base64');
    }

    const decoded = Buffer.from(publicKeyBase64, 'base64');

    return decoded.subarray(0, header.length).equals(header) ? decoded.subarray(header.length) : decoded;
}

/**
 * True when privateKey·G is the public key: the reconstructed key is the vault's key, not a value
 * built from the wrong or missing key parts.
 *
 * @param {string} curve
 * @param {string} privateKeyHex
 * @param {Buffer} rawPublicKey the encoded public point
 * @returns {boolean}
 */
function privateKeyMatchesPublicKey(curve, privateKeyHex, rawPublicKey) {
    const privateKey = new BN(privateKeyHex, 16);
    if (privateKey.isZero()) {
        return false;
    }

    const generator = curve === CURVE.SECP256K1 ? ecdsa.g : eddsa.g;

    return generator.mul(privateKey).eq(decodePoint(curve, rawPublicKey));
}

module.exports = {
    decodePoint: decodePoint,
    encodePoint: encodePoint,
    extractCurveFromPublicKey: extractCurveFromPublicKey,
    rawPublicKeyFromBackup: rawPublicKeyFromBackup,
    privateKeyMatchesPublicKey: privateKeyMatchesPublicKey,
}