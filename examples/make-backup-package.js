'use strict';

// Builds examples/data/backup_package_ecies_p256_v1.json: an ecies-p256-v1
// backup package sealed toward the recovery words of the format's public test
// vector (entropy 00..1f), with a secp256k1 and an ed25519 key each split
// 3-of-3 by a fixed degree-2 polynomial. Deterministic, so the committed file
// and the keys the tests expect never drift. Nothing in it is a real vault.

const fs = require('fs');
const path = require('path');
const BN = require('bn.js');
const {curves} = require('elliptic');
const eciesUtils = require('../src/lib/utils/ecies');
const PACKAGE = require('../src/lib/enumerations/backupPackage');

const WORDS = 'abandon amount liar amount expire adjust cage candy arch gather drum bullet ' +
    'absurd math era live bid rhythm alien crouch range attend journey unaware';

// p(x) = secret + a1*x + a2*x^2 (mod n); share index i is p(i + 1).
const KEYS = [
    {
        keyId: 'k-secp',
        algorithm: 'secp256k1',
        secret: '1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd',
        coefficients: ['0101010101010101010101010101010101010101010101010101010101010101',
            '0202020202020202020202020202020202020202020202020202020202020202'],
    },
    {
        keyId: 'k-ed',
        algorithm: 'ed25519',
        secret: '0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829',
        coefficients: ['0303030303030303030303030303030303030303030303030303030303030303',
            '0404040404040404040404040404040404040404040404040404040404040404'],
    },
];

const CHAIN_CODE = 'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf';

// A counter stands in for the random ephemeral keys and nonces, so the file is reproducible.
let draw = 0x50;
const fixed = () => {
    draw += 1;

    return {ephemeral: Buffer.alloc(32, draw), nonce: Buffer.alloc(PACKAGE.NONCE_BYTES, draw)};
};

const evaluate = (key, x) => {
    const n = curves[key.algorithm].n;
    const secret = new BN(key.secret, 16);
    const [a1, a2] = key.coefficients.map(c => new BN(c, 16));
    const point = new BN(x);

    return secret.add(a1.mul(point)).add(a2.mul(point).mul(point)).umod(n).toArrayLike(Buffer, 'be', 32);
};

function build() {
    const {publicKeyHex} = eciesUtils.recoveryKeyFromWords(WORDS.split(' '));
    const shares = [];

    for (const key of KEYS) {
        for (const index of PACKAGE.SHARE_INDICES) {
            const label = {keyId: key.keyId, index: index, algorithm: key.algorithm};
            shares.push(eciesUtils.sealPart(publicKeyHex, label, evaluate(key, index + 1), fixed()));
        }
    }

    // The browser's transport identity: in the file, not a share, ignored by the tool.
    shares.push(eciesUtils.sealPart(publicKeyHex, {keyId: PACKAGE.IDENTITY_KEY_ID, index: 2, algorithm: 'identity'},
        Buffer.from('identity_0123456789abcdef', 'utf8'), fixed()));

    return {
        version: PACKAGE.VERSION,
        createdAt: 1759660000000,
        walletId: 'example-vault-0001',
        recipientPublicKey: publicKeyHex,
        keys: KEYS.map(key => ({keyId: key.keyId, algorithm: key.algorithm})),
        shares: shares,
        chainCode: eciesUtils.sealPart(publicKeyHex, PACKAGE.CHAIN_CODE_LABEL, Buffer.from(CHAIN_CODE, 'hex'), fixed()),
    };
}

module.exports = {WORDS: WORDS, KEYS: KEYS, CHAIN_CODE: CHAIN_CODE, build: build};

if (require.main === module) {
    const target = path.join(__dirname, 'data', 'backup_package_ecies_p256_v1.json');
    fs.writeFileSync(target, JSON.stringify(build(), null, 2) + '\n');
    fs.writeFileSync(path.join(__dirname, 'data', 'recovery_words.txt'), WORDS + '\n');
    console.log(`wrote ${target}`);
}
