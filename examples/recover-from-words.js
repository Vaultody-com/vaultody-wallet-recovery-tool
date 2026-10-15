'use strict';

// Opens the example ecies-p256-v1 backup package with its 24 recovery words
// and prints what the tool shows: one master key per algorithm.

const fs = require('fs').promises;
const path = require('path');
const RecoveryToolService = require('../src/lib/services/recoveryToolService');
const BackupPackageEntity = require('../src/lib/entities/backupPackageEntity');
const eciesUtils = require('../src/lib/utils/ecies');

(async () => {
    const dataDir = path.join(__dirname, 'data');
    const backupPackage = JSON.parse(await fs.readFile(path.join(dataDir, 'backup_package_ecies_p256_v1.json'), 'utf8'));
    const words = eciesUtils.normaliseWords(await fs.readFile(path.join(dataDir, 'recovery_words.txt'), 'utf8'));

    console.time('recoverFromWords');
    const result = new RecoveryToolService().recoverFromWords(new BackupPackageEntity(backupPackage), words);
    console.timeEnd('recoverFromWords');

    console.log(`vault ${result.walletId}`);
    for (const key of result.keys) {
        console.log(`${key.keyId} (${key.algorithm})`);
        console.log(`  xpriv      ${key.xpriv}`);
        if (key.xpub) {
            console.log(`  xpub       ${key.xpub}`);
        }
        console.log(`  public key ${key.publicKey}`);
    }
})();
