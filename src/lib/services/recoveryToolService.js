'use strict';

const crypto = require("crypto");
const xpubUtils = require('../utils/xpub');
const sjcl = require('sjcl');
const privateKeyTypeEnum = require("../enumerations/privateKeyType");
const eciesUtils = require('../utils/ecies');
const masterKeyUtils = require('../utils/masterKey');

class RecoveryToolService {

    /**
     * @param {string} password
     * @return {{privateKey: string, publicKey: string}}
     */
    generateRsaKeyPair(password) {
        const options = {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'pkcs1',
                format: 'pem',
            },
            privateKeyEncoding: {
                type: 'pkcs1',
                format: 'pem',
            },
        };

        const {privateKey, publicKey} = crypto.generateKeyPairSync("rsa", options);
        const encryptedPrivateKey = sjcl.encrypt(password, privateKey, {ks: 256, mode: "gcm"});
        return {
            publicKey: publicKey,
            privateKey: encryptedPrivateKey,
        }
    }

    /**
     * @param {RecoveryDataEntity} recoveryData
     * @param {Buffer} privateKeyBuffer
     * @param {string} privateKeyType
     * @param {string|null} password
     * @return {string}
     */
    recoverXpriv(recoveryData, privateKeyBuffer, privateKeyType, password = null) {
        let rsaPrivateKey;
        try {
            rsaPrivateKey = privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED)
                ? sjcl.decrypt(password, privateKeyBuffer.toString())
                : privateKeyBuffer.toString();
        } catch (e) {
            throw new Error("Invalid password!");
        }

        const privateKey = recoveryData.recoverPrivateKey(rsaPrivateKey);
        const chainCode = recoveryData.recoverChainCode(rsaPrivateKey);

        return xpubUtils.generateXpriv({curve: recoveryData.getCurve(), chainCode, key: privateKey});
    }

    /**
     * The embedded-wallet (WaaS) path: the 24 recovery words open every sealed
     * part of the ecies-p256-v1 package, and each key is rebuilt from its three
     * shares. Nothing here touches the disk or the network; the recovery scalar
     * is wiped before this returns.
     *
     * @param {BackupPackageEntity} backupPackage
     * @param {string[]} words
     * @return {{walletId: string, createdAt: number|null, keys: {keyId: string, algorithm: string, xpriv: string, xpub: string|null, privateKey: string, publicKey: string}[]}}
     */
    recoverFromWords(backupPackage, words) {
        const recoveryKey = eciesUtils.recoveryKeyFromWords(words);
        try {
            backupPackage.assertSealedToward(recoveryKey.publicKeyHex);

            const keys = backupPackage.getKeys().map(key => {
                const privateKey = backupPackage.recoverPrivateKey(recoveryKey.d, key);
                const chainCode = backupPackage.recoverChainCode(recoveryKey.d, key);

                return {
                    keyId: key.keyId,
                    algorithm: key.algorithm,
                    ...masterKeyUtils.describeMasterKey(key.algorithm, privateKey, chainCode),
                };
            });

            return {
                walletId: backupPackage.getWalletId(),
                createdAt: backupPackage.getCreatedAt(),
                keys: keys,
            };
        } finally {
            recoveryKey.d.fill(0);
        }
    }

}

module.exports = RecoveryToolService;
