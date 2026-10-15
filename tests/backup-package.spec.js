'use strict';

// The ecies-p256-v1 library, without Electron: the format's public test
// vectors (docs/backup-package-ecies-p256-v1.md in the widget SDK, pinned by
// the wallet host, its mock and vaultody-mpc-core pkg/backup), then a whole
// package round trip and every refusal the issue asks for.

const {test, expect} = require('@playwright/test');
const HDKey = require('hdkey');
const BN = require('bn.js');
const {eddsa: EDDSA} = require('elliptic');
const eciesUtils = require('../src/lib/utils/ecies');
const PACKAGE = require('../src/lib/enumerations/backupPackage');
const BackupPackageEntity = require('../src/lib/entities/backupPackageEntity');
const RecoveryToolService = require('../src/lib/services/recoveryToolService');
const example = require('../examples/make-backup-package');

const VECTOR = {
    words: 'abandon amount liar amount expire adjust cage candy arch gather drum bullet ' +
        'absurd math era live bid rhythm alien crouch range attend journey unaware',
    d: 'c45c529c8ab0a0f1a4b2b0ff417effdea05120d24eae52350f9b63f2e9cbfb7c',
    Q: '04fd58364a553cca0485860c7985b3a9effbfbc0f6a92c6ffe5087b6c6c2553decd51c30fac0e61d91143f7eeb0acbf50e7d84ae0c6ff9f6cb18209c18e44c1da7',
    label: {keyId: 'k-secp', index: 2, algorithm: 'secp256k1'},
    plaintext: 'share_0123456789abcdef',
    ephemeralScalar: Buffer.from(Array.from({length: 32}, (_, i) => 0x20 + i)),
    nonce: Buffer.from(Array.from({length: 12}, (_, i) => 0x40 + i)),
    part: {
        keyId: 'k-secp',
        index: 2,
        algorithm: 'secp256k1',
        ephemeralPublicKey: '04c6559d416dfb56af714f146d917c24abf818b2fb121604129649848230a2d258b2a6d82dc6c6734cf092ffaa9fc012f10f7008d3952a08d5797e85feaba5d977',
        nonce: 'QEFCQ0RFRkdISUpL',
        ciphertext: '0Ak1vOp+KPlveU/1xQJn3TjJxEej+JkZ3zxD5Rt9I2a0Rf82wEU=',
    },
};

const words = () => VECTOR.words.split(' ');
const clone = value => JSON.parse(JSON.stringify(value));
const recover = backupPackage => new RecoveryToolService().recoverFromWords(new BackupPackageEntity(backupPackage), words());

test.describe('words to recovery key', () => {
    test('the vector words derive the vector d and Q', () => {
        const key = eciesUtils.recoveryKeyFromWords(words());

        expect(key.d.toString('hex')).toBe(VECTOR.d);
        expect(key.publicKeyHex).toBe(VECTOR.Q);
        expect(key.Q.toString('hex')).toBe(VECTOR.Q);
    });

    test('case and whitespace do not change the key', () => {
        const shouted = '  ' + VECTOR.words.toUpperCase().replace(/ /g, '   ') + '\n';

        expect(eciesUtils.recoveryKeyFromWords(eciesUtils.normaliseWords(shouted)).publicKeyHex).toBe(VECTOR.Q);
    });

    test('12 words, a bad checksum and a word off the list are refused', () => {
        const list = words();
        const swapped = words();
        [swapped[0], swapped[1]] = [swapped[1], swapped[0]];

        for (const bad of [list.slice(0, 12), swapped, [...list.slice(0, 23), 'vaultody'], []]) {
            expect(eciesUtils.validRecoveryWords(bad)).toBe(false);
            expect(() => eciesUtils.recoveryKeyFromWords(bad)).toThrow(eciesUtils.RecoveryWordsError);
        }
    });
});

test.describe('a sealed part', () => {
    test('sealing with the vector ephemeral key and nonce reproduces the vector bytes', () => {
        const part = eciesUtils.sealPart(VECTOR.Q, VECTOR.label, Buffer.from(VECTOR.plaintext, 'utf8'),
            {ephemeral: VECTOR.ephemeralScalar, nonce: VECTOR.nonce});

        expect(part).toEqual(VECTOR.part);
    });

    test('the vector part opens with the words, and only in its place', () => {
        const key = eciesUtils.recoveryKeyFromWords(words());

        expect(eciesUtils.openPart(key.d, key.Q, VECTOR.part).toString('utf8')).toBe(VECTOR.plaintext);

        for (const moved of [{index: 0}, {keyId: 'k-ed'}, {algorithm: 'ed25519'}]) {
            expect(() => eciesUtils.openPart(key.d, key.Q, {...VECTOR.part, ...moved})).toThrow(eciesUtils.SealedPartError);
        }
    });

    test('another set of words is another key', () => {
        const other = eciesUtils.recoveryKeyFromWords(
            require('bip39').entropyToMnemonic(Buffer.from(Array.from({length: 32}, (_, i) => 1 + i))).split(' ')
        );

        expect(() => eciesUtils.openPart(other.d, other.Q, VECTOR.part)).toThrow(eciesUtils.SealedPartError);
    });

    test('a malformed ephemeral key, nonce or ciphertext is refused before any crypto', () => {
        const key = eciesUtils.recoveryKeyFromWords(words());

        for (const broken of [{ephemeralPublicKey: '04' + 'ab'.repeat(64)}, {nonce: 'QUJD'}, {ciphertext: 'QUJD'}]) {
            expect(() => eciesUtils.openPart(key.d, key.Q, {...VECTOR.part, ...broken})).toThrow(eciesUtils.SealedPartError);
        }
    });

    test('every seal draws its own ephemeral key and nonce', () => {
        const first = eciesUtils.sealPart(VECTOR.Q, VECTOR.label, Buffer.from('same'));
        const second = eciesUtils.sealPart(VECTOR.Q, VECTOR.label, Buffer.from('same'));

        expect(first.ephemeralPublicKey).not.toBe(second.ephemeralPublicKey);
        expect(first.nonce).not.toBe(second.nonce);
    });
});

test('a recipient must be an uncompressed point on P-256', () => {
    expect(eciesUtils.validRecipient(VECTOR.Q)).toBe(true);

    for (const bad of ['04' + 'ab'.repeat(64), '02' + VECTOR.Q.slice(2, 66), VECTOR.Q.toUpperCase(), VECTOR.Q.slice(0, 128), '', null]) {
        expect(eciesUtils.validRecipient(bad)).toBe(false);
    }
});

test.describe('the example package', () => {
    test('the committed file is what the generator builds', () => {
        expect(require('../examples/data/backup_package_ecies_p256_v1.json')).toEqual(example.build());
    });

    test('opens with its words to the keys it was split from', () => {
        const result = recover(example.build());
        const [secp, ed] = example.KEYS;

        expect(result.walletId).toBe('example-vault-0001');
        expect(result.keys.map(key => key.keyId)).toEqual([secp.keyId, ed.keyId]);

        // secp256k1: the extended key an independent HD library builds from the
        // same master key and chain code, and its public half.
        const hd = new HDKey();
        hd.chainCode = Buffer.from(example.CHAIN_CODE, 'hex');
        hd.privateKey = Buffer.from(secp.secret, 'hex');
        expect(result.keys[0]).toMatchObject({
            algorithm: 'secp256k1',
            xpriv: hd.privateExtendedKey,
            xpub: hd.publicExtendedKey,
            privateKey: secp.secret,
            publicKey: hd.publicKey.toString('hex'),
        });

        // ed25519: the scalar itself and scalar * B.
        const eddsa = new EDDSA('ed25519');
        expect(result.keys[1]).toMatchObject({
            algorithm: 'ed25519',
            privateKey: ed.secret,
            xpub: null,
            publicKey: Buffer.from(eddsa.encodePoint(eddsa.curve.g.mul(new BN(ed.secret, 16)))).toString('hex'),
        });
        expect(result.keys[1].xpriv).toMatch(/^xprv/);
    });

    test('the mpc-identity entry is carried but never treated as a share', () => {
        const backupPackage = example.build();

        expect(backupPackage.shares.some(part => part.keyId === PACKAGE.IDENTITY_KEY_ID)).toBe(true);
        expect(new BackupPackageEntity(backupPackage).getSharesOf(PACKAGE.IDENTITY_KEY_ID)).toEqual({});
    });

    test('wrong words are told apart from a broken file', () => {
        const other = require('bip39').entropyToMnemonic(Buffer.alloc(32, 7)).split(' ');

        expect(() => new RecoveryToolService().recoverFromWords(new BackupPackageEntity(example.build()), other))
            .toThrow('These are not the recovery words of this backup file.');
    });

    test('a share moved to another index is refused', () => {
        const backupPackage = example.build();
        const [first, second] = backupPackage.shares.filter(part => part.keyId === 'k-secp');
        [first.index, second.index] = [second.index, first.index];

        expect(() => recover(backupPackage)).toThrow(/does not open with these words at this place/);
    });

    test('a tampered ciphertext is refused', () => {
        const backupPackage = example.build();
        const part = backupPackage.shares.find(share => share.keyId === 'k-ed');
        const bytes = Buffer.from(part.ciphertext, 'base64');
        bytes[3] ^= 0x01;
        part.ciphertext = bytes.toString('base64');

        expect(() => recover(backupPackage)).toThrow(/altered/);
    });

    test('an unknown version is refused by name', () => {
        expect(() => recover({...example.build(), version: 'ecies-p256-v2'}))
            .toThrow('Unsupported backup package version "ecies-p256-v2": this tool opens "ecies-p256-v1".');
    });

    test('a missing share, a missing chain code and an unknown algorithm are refused', () => {
        const missingShare = example.build();
        missingShare.shares = missingShare.shares.filter(part => !(part.keyId === 'k-secp' && part.index === 1));
        expect(() => recover(missingShare)).toThrow('The backup package is missing share 1 of key k-secp.');

        const noChainCode = clone(example.build());
        delete noChainCode.chainCode;
        expect(() => recover(noChainCode)).toThrow('The backup package carries no master chain code.');

        const oddCurve = example.build();
        oddCurve.keys[0].algorithm = 'bls12-381';
        expect(() => recover(oddCurve)).toThrow(/unknown algorithm/);
    });

    test('a package sealed toward another recipient is refused before any part is opened', () => {
        const backupPackage = example.build();
        backupPackage.recipientPublicKey = VECTOR.part.ephemeralPublicKey;

        expect(() => recover(backupPackage)).toThrow('These are not the recovery words of this backup file.');
    });
});
