'use strict';

const XPRV_BYTES_LENGTH = 78;
const XPRIV_VERSION = 0x0488ADE4;
const b58 = require('bs58check');
const HDKey = require("hdkey");
const {CURVE} = require("../enumerations/curve");

/**
 * @param {string} curve
 * @param {string} chainCode
 * @param {string} key
 * return {string}
 */
function generateXpriv({curve, chainCode, key}) {
    switch (curve) {
        case CURVE.ED25519:
            return serialize({
                key: Buffer.from(key, "hex"),
                chainCode: Buffer.from(chainCode, "hex"),
            });
        case CURVE.SECP256K1:
            const hd = new HDKey();
            hd.chainCode = Buffer.from(chainCode, 'hex');
            hd.privateKey = Buffer.from(key, 'hex');

            return hd.privateExtendedKey;
        default:
            throw new Error("Unknown curve");
    }
}

/**
 * @param {Buffer} key
 * @param {Buffer} chainCode
 * @param {number} depth
 * @param {number} fingerprint
 * @param {number} index
 * @return {string}
 */
function serialize({key, chainCode, depth = 0, fingerprint = 0, index = 0}) {
    const buffer = Buffer.allocUnsafe(XPRV_BYTES_LENGTH);
    const preparedKey = Buffer.concat([Buffer.alloc(1, 0), key]);

    buffer.writeUInt8(depth, 4);
    buffer.writeUInt32BE(XPRIV_VERSION, 0);
    buffer.writeUInt32BE(fingerprint, 5);
    buffer.writeUInt32BE(index, 9);
    chainCode.copy(buffer, 13);
    preparedKey.copy(buffer, 45);

    return b58.encode(buffer);
}

module.exports = {
    generateXpriv: generateXpriv,
}
