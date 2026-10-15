'use strict';

const BN = require('bn.js');
const HDKey = require('hdkey');
const {ec: ECDSA, eddsa: EDDSA} = require('elliptic');
const {CURVE} = require('../enumerations/curve');
const xpubUtils = require('./xpub');

const ecdsa = new ECDSA(CURVE.SECP256K1);
const eddsa = new EDDSA(CURVE.ED25519);

/**
 * Everything the tool shows for one recovered master key: the extended
 * private key the RSA path has always produced, plus the public side so a
 * recovery can be checked against the vault without re-deriving anything.
 *
 * @param {string} curve
 * @param {string} privateKeyHex 32 bytes, big-endian
 * @param {string} chainCodeHex 32 bytes
 * @return {{xpriv: string, xpub: string|null, privateKey: string, publicKey: string}}
 */
function describeMasterKey(curve, privateKeyHex, chainCodeHex) {
    const xpriv = xpubUtils.generateXpriv({curve: curve, chainCode: chainCodeHex, key: privateKeyHex});

    switch (curve) {
        case CURVE.SECP256K1:
            return {
                xpriv: xpriv,
                xpub: HDKey.fromExtendedKey(xpriv).publicExtendedKey,
                privateKey: privateKeyHex,
                publicKey: ecdsa.keyFromPrivate(privateKeyHex, 'hex').getPublic(true, 'hex'),
            };
        case CURVE.ED25519:
            // The platform stores the ed25519 scalar big-endian and derives the
            // point as scalar * B; the extended key has no public form for this curve.
            return {
                xpriv: xpriv,
                xpub: null,
                privateKey: privateKeyHex,
                publicKey: Buffer.from(eddsa.encodePoint(eddsa.curve.g.mul(new BN(privateKeyHex, 16)))).toString('hex'),
            };
        default:
            throw new Error('Unknown curve');
    }
}

module.exports = {
    describeMasterKey: describeMasterKey,
};
