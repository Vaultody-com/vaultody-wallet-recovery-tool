// Building blocks for the recovery screen. Loaded after common.js.

const XPRIV_PREFIX = 'xprv';

/**
 * @param {{id: string, title: string, sub: string, icon: string}} options
 * @return {string}
 */
function pickerMarkup(options) {
    return `
        <div class="picker" id="${options.id}Picker">
            <div class="pic">${window.ui.icon(options.icon || 'file', '', 19)}</div>
            <div>
                <div class="ptitle">${options.title}</div>
                <div class="psub" id="${options.id}Text">${options.sub}</div>
            </div>
            <button id="${options.id}Button" type="button" class="btn btn-ghost btn-sm">Choose file</button>
        </div>
        <div class="field-status" id="${options.id}Status"></div>`;
}

/**
 * Reflects the validation outcome of a chosen file on its picker.
 *
 * @param {string} id
 * @param {boolean} valid
 */
function setPickerStatus(id, valid) {
    const picker = document.getElementById(`${id}Picker`);
    const status = document.getElementById(`${id}Status`);

    if (picker) {
        picker.classList.toggle('loaded', valid);
        picker.classList.toggle('invalid', !valid);
    }

    if (status) {
        status.className = `field-status ${valid ? 'ok' : 'bad'}`;
        status.innerHTML = valid
            ? `${window.ui.icon('checkCircle', '', 13)} File accepted`
            : `${window.ui.icon('warning', '', 13)} File rejected &mdash; wrong format or corrupted`;
    }
}

/**
 * Renders the outcome of a recovery attempt. A recovered xPriv is masked until
 * the reader explicitly reveals it; anything else is an error message.
 *
 * @param {HTMLElement} container
 * @param {string|Error|object} result
 */
function renderRecoveryResult(container, result) {
    const text = String(result && result.message ? result.message : result);

    if (!text.startsWith(XPRIV_PREFIX)) {
        container.innerHTML = `
            <div class="result-card">
                <div class="result-head">
                    <div class="rok rbad">${window.ui.icon('warning', '', 18)}</div>
                    <h3>Recovery failed</h3>
                </div>
                <p class="result-lede" id="recoveryResult"></p>
            </div>`;
        document.getElementById('recoveryResult').textContent = text;

        return;
    }

    container.innerHTML = `
        <div class="result-card safe">
            <div class="result-head">
                <div class="rok">${window.ui.icon('check', '', 18)}</div>
                <h3>Recovery successful</h3>
            </div>
            <p class="result-lede">Your master extended private key was reconstructed on this device. Import it into a
                trusted wallet application while still offline, then wipe it from this machine.</p>
            <div class="kv danger">
                <div class="kvl">
                    ${window.ui.icon('lock', '', 13)} Master xPriv
                    <span class="pill">handle with extreme care</span>
                </div>
                <pre class="key-body masked" id="recoveryResult"></pre>
                <div class="key-actions">
                    <button id="reveal-xpriv" type="button" class="btn btn-ghost btn-sm"></button>
                    <button id="copy-xpriv" type="button" class="btn btn-ghost btn-sm"></button>
                    <button id="download-xpriv" type="button" class="btn btn-ghost btn-sm"></button>
                </div>
            </div>
            <div class="note danger">
                ${window.ui.icon('warning', '', 17)}
                <span>This key controls every address in the vault. Anyone who reads it can move the funds.</span>
            </div>
        </div>`;

    const copyButton = document.getElementById('copy-xpriv');
    const downloadButton = document.getElementById('download-xpriv');

    copyButton.innerHTML = `${window.ui.icon('copy', '', 15)} Copy`;
    downloadButton.innerHTML = `${window.ui.icon('download', '', 15)} Download`;

    window.ui.wireSecretReveal(
        document.getElementById('recoveryResult'),
        document.getElementById('reveal-xpriv'),
        text
    );

    copyButton.addEventListener('click', () => {
        window.ui.copySecret(text, 'Master xPriv');
    });

    downloadButton.addEventListener('click', () => {
        window.ui.downloadSecret(text, 'master_xpriv.txt');
    });
}

/**
 * @param {string} id
 * @param {string} label
 * @return {string}
 */
function passwordFieldMarkup(id, label) {
    return `
        <div class="field-label">${label}</div>
        <div class="secret-row">
            <input type="password" id="${id}" class="input" aria-label="${label}" />
            <button type="button" class="icon-btn" id="${id}-reveal" title="Reveal"
                aria-label="Reveal or hide the password"></button>
        </div>`;
}

window.recovery = {
    pickerMarkup,
    setPickerStatus,
    renderRecoveryResult,
    passwordFieldMarkup,
};
