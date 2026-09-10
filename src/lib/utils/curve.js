'use strict';

const { CURVE, PREFIXES } = require("../enumerations/curve");
const { ec: ECDSA, eddsa: EDDSA } = require("elliptic");
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
 * Encodes a curve point the way mpc-node does: SEC1 COMPRESSED for secp256k1 (33 bytes, an 02/03
 * parity prefix over the 32-byte X), and the 32-byte little-endian Y-with-sign-bit form for
 * ed25519.
 *
 * @param {string} curve
 * @param {Point} point
 * @return {Buffer}
 */
function encodePoint(curve, point) {
    switch (curve) {
        case CURVE.SECP256K1:
            // elliptic puts encoding on the POINT, not on the curve: short.js defines
            // decodePoint but no encodePoint, so ecdsa.curve.encodePoint(point) was a
            // "not a function" TypeError on every call. That is why this function had no
            // call sites. The second argument selects the compressed form.
            return Buffer.from(point.encode('array', true));
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

module.exports = {
    decodePoint: decodePoint,
    encodePoint: encodePoint,
    extractCurveFromPublicKey: extractCurveFromPublicKey
}