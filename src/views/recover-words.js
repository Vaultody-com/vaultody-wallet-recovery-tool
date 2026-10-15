// The embedded-wallet recovery screen: the e-mailed ecies-p256-v1 backup file
// and the 24 recovery words. The words are read from the textarea when the
// button is pressed and go to the main process and nowhere else.

let backupPackagePath;

document.getElementById('recoverWordsButton').innerHTML =
    `${window.ui.icon('shield', '', 16)} Recover master keys`;

document.getElementById('backupPackageFileField').innerHTML = window.recovery.pickerMarkup({
    id: 'backupPackageFile',
    icon: 'file',
    title: 'Backup file',
    sub: 'The vaultody-backup-….json attached to the e-mail you received when you backed up',
});

document.getElementById('backupPackageFileButton').addEventListener('click', () => {
    window.api.invoke('file:backup-package').then(result => {
        if (!result.canceled) {
            document.getElementById('backupPackageFileText').innerText = result.filePaths[0];
            backupPackagePath = result.filePaths[0];
        }
    });
});

window.ui.wireTextareaReveal(
    document.getElementById('recoveryWords-reveal'),
    document.getElementById('recoveryWords')
);

/**
 * One recovered master key: the extended private key masked until revealed,
 * the public half in the clear, since it is what a recovery is checked against.
 *
 * @param {{keyId: string, algorithm: string, xpriv: string, xpub: string|null, publicKey: string}} key
 * @param {number} position
 * @return {string}
 */
function keyMarkup(key, position) {
    const publicLabel = key.xpub ? 'Master xPub' : 'Public key';

    return `
        <div class="kv danger">
            <div class="kvl">
                ${window.ui.icon('lock', '', 13)} ${key.algorithm} &middot; master xPriv
                <span class="pill">handle with extreme care</span>
            </div>
            <pre class="key-body masked" id="recoveryResult-${position}"></pre>
            <div class="key-actions">
                <button id="reveal-xpriv-${position}" type="button" class="btn btn-ghost btn-sm"></button>
                <button id="copy-xpriv-${position}" type="button" class="btn btn-ghost btn-sm"></button>
                <button id="download-xpriv-${position}" type="button" class="btn btn-ghost btn-sm"></button>
            </div>
        </div>
        <div class="kv">
            <div class="kvl">${window.ui.icon('key', '', 13)} ${key.algorithm} &middot; ${publicLabel}</div>
            <pre class="key-body" id="recoveryPublic-${position}"></pre>
        </div>`;
}

/**
 * @param {HTMLElement} container
 * @param {{error?: string, walletId?: string, keys?: object[]}} result
 */
function renderWordsRecoveryResult(container, result) {
    if (!result || result.error || !Array.isArray(result.keys)) {
        container.innerHTML = `
            <div class="result-card">
                <div class="result-head">
                    <div class="rok rbad">${window.ui.icon('warning', '', 18)}</div>
                    <h3>Recovery failed</h3>
                </div>
                <p class="result-lede" id="recoveryResult"></p>
            </div>`;
        document.getElementById('recoveryResult').textContent =
            result && result.error ? result.error : 'The backup file could not be opened.';

        return;
    }

    container.innerHTML = `
        <div class="result-card safe">
            <div class="result-head">
                <div class="rok">${window.ui.icon('check', '', 18)}</div>
                <h3>Recovery successful</h3>
            </div>
            <p class="result-lede">The master keys of vault <b id="recoveryWalletId"></b> were reconstructed on this
                device, one per curve. Import them into a trusted wallet application while still offline, then wipe
                them from this machine.</p>
            ${result.keys.map(keyMarkup).join('')}
            <div class="note danger">
                ${window.ui.icon('warning', '', 17)}
                <span>These keys control every address in the vault. Anyone who reads them can move the funds.</span>
            </div>
        </div>`;

    document.getElementById('recoveryWalletId').textContent = result.walletId;

    result.keys.forEach((key, position) => {
        const copyButton = document.getElementById(`copy-xpriv-${position}`);
        const downloadButton = document.getElementById(`download-xpriv-${position}`);
        const label = `${key.algorithm} master xPriv`;

        copyButton.innerHTML = `${window.ui.icon('copy', '', 15)} Copy`;
        downloadButton.innerHTML = `${window.ui.icon('download', '', 15)} Download`;

        window.ui.wireSecretReveal(
            document.getElementById(`recoveryResult-${position}`),
            document.getElementById(`reveal-xpriv-${position}`),
            key.xpriv
        );
        copyButton.addEventListener('click', () => window.ui.copySecret(key.xpriv, label));
        downloadButton.addEventListener('click', () => window.ui.downloadSecret(key.xpriv, `master_xpriv_${key.algorithm}.txt`));

        document.getElementById(`recoveryPublic-${position}`).textContent = key.xpub || key.publicKey;
    });
}

const recoveryResultContainer = document.getElementById('recoveryResultContainer');
document.getElementById('recoverWordsButton').addEventListener('click', () => {
    const words = document.getElementById('recoveryWords').value;
    if (!words.trim()) {
        alert('Type your 24 recovery words first!');

        return;
    }

    recoveryResultContainer.innerHTML = window.ui.spinnerMarkup('Opening the backup and rebuilding the keys&hellip;');

    window.api.invoke('recover:recover-from-words', backupPackagePath, words).then(result => {
        renderWordsRecoveryResult(recoveryResultContainer, result);
    });
});

window.api.receive('status:backup-package', (status) => {
    window.recovery.setPickerStatus('backupPackageFile', status);
});
