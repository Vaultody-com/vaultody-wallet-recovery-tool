'use strict';

const {test, expect} = require('@playwright/test');
const BN = require('bn.js');
const {ec: ECDSA} = require('elliptic');

const curveUtils = require('../src/lib/utils/curve');
const {CURVE} = require('../src/lib/enumerations/curve');

const secp256k1 = new ECDSA(CURVE.SECP256K1);

// Published secp256k1 known-answer vectors: the scalar and the SEC1 COMPRESSED encoding of kG,
// where the 02/03 prefix is the parity of Y. These are the reference values, not something this
// repo produced — a regression in encodePoint cannot move them.
const SECP256K1_VECTORS = [
    {
        scalar: '0000000000000000000000000000000000000000000000000000000000000001',
        compressed: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    },
    {
        scalar: '0000000000000000000000000000000000000000000000000000000000000002',
        compressed: '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
    },
    {
        scalar: '0000000000000000000000000000000000000000000000000000000000000003',
        compressed: '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
    },
    {
        scalar: 'aa5e28d6a97a2479a65527f7290311a3624d4cc0fa1578598ee3c2613bf99522',
        compressed: '0234f9460f0e4f08393d192b3c5133a6ba099aa0ad9fd54ebccfacdfa239ff49c6',
    },
    {
        // The one vector here with an ODD Y, so the 03 prefix is exercised too.
        scalar: '7e2b897b8cebc6361663ad410835639826d590f393d90a9538881735256dfae3',
        compressed: '03d74bf844b0862475103d96a611cf2d898447e288d34b360bc885cb8ce7c00575',
    },
];

// RFC 8032 ed25519 public keys — already 32-byte encoded points, so encode(decode(x)) === x.
const ED25519_ENCODED_POINTS = [
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
];

test('encodePoint returns the 33-byte compressed encoding for every secp256k1 vector', () => {
    for (const vector of SECP256K1_VECTORS) {
        const point = secp256k1.g.mul(new BN(vector.scalar, 16));
        const encoded = curveUtils.encodePoint(CURVE.SECP256K1, point);

        expect(Buffer.isBuffer(encoded)).toBe(true);
        expect(encoded.length).toBe(33);
        expect(encoded.toString('hex')).toBe(vector.compressed);
        expect([0x02, 0x03]).toContain(encoded[0]);
    }
});

test('a secp256k1 point survives encode then decode', () => {
    for (const vector of SECP256K1_VECTORS) {
        const point = secp256k1.g.mul(new BN(vector.scalar, 16));
        const roundTripped = curveUtils.decodePoint(
            CURVE.SECP256K1,
            curveUtils.encodePoint(CURVE.SECP256K1, point)
        );

        expect(roundTripped.eq(point)).toBe(true);
    }
});

test('encodePoint still returns the 32-byte ed25519 encoding', () => {
    for (const encodedPoint of ED25519_ENCODED_POINTS) {
        const point = curveUtils.decodePoint(CURVE.ED25519, Buffer.from(encodedPoint, 'hex'));
        const encoded = curveUtils.encodePoint(CURVE.ED25519, point);

        expect(Buffer.isBuffer(encoded)).toBe(true);
        expect(encoded.length).toBe(32);
        expect(encoded.toString('hex')).toBe(encodedPoint);
    }
});

test('an unknown curve is refused rather than silently mis-encoded', () => {
    const point = secp256k1.g;

    expect(() => curveUtils.encodePoint('p256', point)).toThrow('Unknown curve');
});
