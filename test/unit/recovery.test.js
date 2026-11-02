'use strict';

// Recovery checks the key it rebuilds against the vault's public key, and merges a server co-signer
// vault's client share into the Vaultody backup. Runs with `npm run test:unit` (node:test, no Electron).

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const BN = require('bn.js');
const bip39 = require('bip39');
const HDKey = require('hdkey');
const { ec: EC } = require('elliptic');

const RecoveryDataEntity = require('../../src/lib/entities/recoveryDataEntity');
const RecoveryToolService = require('../../src/lib/services/recoveryToolService');
const RecoverService = require('../../src/services/recover');
const curveUtils = require('../../src/lib/utils/curve');
const privateKeyType = require('../../src/lib/enumerations/privateKeyType');
const { CURVE, PREFIXES, DOMAIN_PARAMS } = require('../../src/lib/enumerations/curve');

const { KEY_MISMATCH_MESSAGE } = RecoveryToolService;
const EXAMPLES = path.join(__dirname, '../../examples/data');
const EXAMPLE_RSA_KEY = fs.readFileSync(path.join(EXAMPLES, 'private_key.txt'));
const EXPECTED_ECDSA_XPRIV =
    'xprv9s21ZrQH143K24jyDYVEDbpcreer9Bu9REH8Xf48P5W2rF4jcBqgqFqPpxDF1ZJwoYsm6QTvTbn75mRbPTtq87hpD8YtG6A2MaJUmMP2Enw';
const secp256k1 = new EC('secp256k1');
const n = DOMAIN_PARAMS[CURVE.SECP256K1].n;

const example = name => JSON.parse(fs.readFileSync(path.join(EXAMPLES, name)));

/**
 * A server co-signer vault's key as a 3-of-3 Shamir sharing: Vaultody's players 0 and 1 in the
 * backup, the client's player 3 in their own share file. Each part is RSA-OAEP encrypted to the
 * client's recovery key, as the nodes export them.
 *
 * @return {{privateKey: BN, rsaPrivateKeyPem: string, backup: object, cosignerShare: object}}
 */
function serverCosignerVault() {
    const { publicKey: rsaPublicKey, privateKey: rsaPrivateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const encrypt = data => crypto.publicEncrypt({
        key: rsaPublicKey,
        oaepHash: 'sha256',
    }, data).toString('base64');
    const scalar = () => new BN(crypto.randomBytes(32)).umod(n);

    const privateKey = scalar();
    const a1 = scalar();
    const a2 = scalar();
    const shareAt = x => privateKey.add(a1.muln(x)).add(a2.muln(x * x)).umod(n);
    const keyPart = index => ({
        index: index,
        data: encrypt(Buffer.from(bip39.entropyToMnemonic(shareAt(index + 1).toString(16, 64)))),
    });

    const rawPublicKey = Buffer.from(secp256k1.g.mul(privateKey).encode('array', false));
    const chainCodeKey = crypto.randomBytes(32);
    const cipher = crypto.createCipheriv('aes-256-gcm', chainCodeKey, Buffer.alloc(12));
    const masterChainCode = Buffer.concat([cipher.update(crypto.randomBytes(32)), cipher.final(), cipher.getAuthTag()]);

    return {
        privateKey: privateKey,
        rsaPrivateKeyPem: rsaPrivateKey.export({
            type: 'pkcs1',
            format: 'pem',
        }),
        backup: {
            public_key: Buffer.from(PREFIXES[CURVE.SECP256K1], 'hex').toString('base64') + rawPublicKey.toString('base64'),
            version: '1',
            sharing_type: 'shamir',
            key_parts: [keyPart(0), keyPart(1)],
            master_chain_code: masterChainCode.toString('base64'),
            master_chain_code_key: encrypt(chainCodeKey),
        },
        cosignerShare: {
            ...keyPart(3),
            publicKey: rawPublicKey.toString('base64'),
        },
    };
}

/**
 * Runs the app's recovery with the given files written to a temporary directory.
 *
 * @param {object} vault
 * @param {object|null} cosignerShare
 * @return {Promise<string|Error>}
 */
async function recover(vault, cosignerShare) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'recovery-test-'));
    const write = (name, content) => {
        const file = path.join(dir, name);
        fs.writeFileSync(file, typeof content === 'string' ? content : JSON.stringify(content));

        return file;
    };

    return new RecoverService().recoverWalletXPriv(
        null,
        write('backup.json', vault.backup),
        write('rsa.pem', vault.rsaPrivateKeyPem),
        privateKeyType.RAW_PEM,
        null,
        cosignerShare ? write('cosigner-share.json', cosignerShare) : null,
    );
}

const messageOf = result => String(result && result.message ? result.message : result);

test('the example backups still recover, and their keys match their public keys', () => {
    const tool = new RecoveryToolService();

    assert.strictEqual(
        tool.recoverXpriv(new RecoveryDataEntity(example('recovery_data_ecdsa.json')), EXAMPLE_RSA_KEY, privateKeyType.RAW_PEM),
        EXPECTED_ECDSA_XPRIV,
    );
    assert.ok(tool.recoverXpriv(new RecoveryDataEntity(example('recovery_data_eddsa.json')), EXAMPLE_RSA_KEY, privateKeyType.RAW_PEM));
});

test('a key rebuilt from too few parts is refused, not shown', () => {
    for (const name of ['recovery_data_ecdsa.json', 'recovery_data_eddsa.json']) {
        const backup = example(name);
        backup.key_parts = backup.key_parts.slice(0, 1);

        assert.throws(
            () => new RecoveryToolService().recoverXpriv(new RecoveryDataEntity(backup), EXAMPLE_RSA_KEY, privateKeyType.RAW_PEM),
            { message: KEY_MISMATCH_MESSAGE },
            name,
        );
    }
});

test('a server co-signer vault recovers its own key once the client share is merged', async () => {
    const vault = serverCosignerVault();

    const result = await recover(vault, vault.cosignerShare);

    assert.match(messageOf(result), /^xprv/);
    assert.strictEqual(HDKey.fromExtendedKey(result).privateKey.toString('hex'), vault.privateKey.toString(16, 64));
});

test('a server co-signer backup recovered without the client share is refused, not shown wrong', async () => {
    const vault = serverCosignerVault();

    const result = await recover(vault, null);

    assert.strictEqual(messageOf(result), KEY_MISMATCH_MESSAGE);
});

test('a client share from another vault is refused before recovery', async () => {
    const vault = serverCosignerVault();
    const other = serverCosignerVault();

    const result = await recover(vault, {
        ...vault.cosignerShare,
        publicKey: other.cosignerShare.publicKey,
    });

    assert.strictEqual(messageOf(result), 'Co-signer share does not match this backup (different vault)');
});

test('a client share whose part the backup already holds is refused', async () => {
    const vault = serverCosignerVault();

    const result = await recover(vault, {
        ...vault.cosignerShare,
        index: 1,
    });

    assert.strictEqual(messageOf(result), 'Co-signer share is already present in the backup file');
});

test('the raw public key is read from both public_key encodings', () => {
    const raw = Buffer.from(secp256k1.g.mul(new BN(7)).encode('array', false));
    const header = Buffer.from(PREFIXES[CURVE.SECP256K1], 'hex');

    assert.deepStrictEqual(curveUtils.rawPublicKeyFromBackup(CURVE.SECP256K1, header.toString('base64') + raw.toString('base64')), raw);
    assert.deepStrictEqual(curveUtils.rawPublicKeyFromBackup(CURVE.SECP256K1, Buffer.concat([header, raw]).toString('base64')), raw);
});
