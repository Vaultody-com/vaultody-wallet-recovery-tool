let ticketPath, recoveryDataPath, rsaPath;

document.getElementById("sealButton").innerHTML =
    `${window.ui.icon('lock', '', 16)} Seal the key parts`;

document.getElementById("ticketFileField").innerHTML = window.recovery.pickerMarkup({
    id: 'ticketFile',
    icon: 'file',
    title: 'Key import ticket',
    sub: 'The .json you downloaded when you started the import',
});

document.getElementById("recoveryDataFileField").innerHTML = window.recovery.pickerMarkup({
    id: 'recoveryDataFile',
    icon: 'file',
    title: 'Backup data file',
    sub: 'The .json you downloaded when you backed up the vault',
});

const ticketFileText = document.getElementById("ticketFileText");
document.getElementById("ticketFileButton").addEventListener("click", function () {
    window.api.invoke("file:key-import-ticket").then(result => {
        if (!result.canceled) {
            ticketFileText.innerText = result.filePaths[0];
            ticketPath = result.filePaths[0];
        }
    });
});

const recoveryDataFileText = document.getElementById("recoveryDataFileText");
document.getElementById("recoveryDataFileButton").addEventListener("click", function () {
    window.api.invoke("file:recovery-data").then(result => {
        if (!result.canceled) {
            recoveryDataFileText.innerText = result.filePaths[0];
            recoveryDataPath = result.filePaths[0];
        }
    });
});

function handlePrivateKeyFileInput() {
    const rsaFileText = document.getElementById("rsaFileText");
    const privateKeyType = document.getElementById("privateKeySelect").value;
    window.api.invoke("file:rsa-key", privateKeyType).then(result => {
        if (!result.canceled) {
            rsaFileText.innerText = result.filePaths[0];
            rsaPath = result.filePaths[0];
        }
    });
}

/**
 * The password only exists for SJCL encrypted keys — a raw PEM key is not password protected,
 * so the field is not rendered at all.
 *
 * @param {boolean} withPassword
 */
function renderPrivateKeyContainer(withPassword) {
    document.getElementById("privateKeyContainer").innerHTML = `
        <div class="form-grid">
            <div>
                <div class="field-label">Private RSA key</div>
                ${window.recovery.pickerMarkup({
                    id: 'rsaFile',
                    icon: 'lock',
                    title: 'RSA private key file',
                    sub: withPassword ? 'The SJCL encrypted key file' : 'The raw PEM key file',
                })}
            </div>
            ${withPassword ? `<div>${window.recovery.passwordFieldMarkup('password', 'Private RSA key password')}</div>` : ''}
        </div>`;

    document.getElementById("rsaFileButton").addEventListener("click", handlePrivateKeyFileInput);

    if (withPassword) {
        window.ui.wireInputReveal(
            document.getElementById("password-reveal"),
            document.getElementById("password")
        );
    }
}

renderPrivateKeyContainer(true);

/**
 * @param {number[]} seats
 * @return {string}
 */
function seatList(seats) {
    return seats.map(seat => `#${seat}`).join(', ');
}

/**
 * Renders the outcome of a sealing run. Success is one file to upload; anything else is an
 * error message, shown as text so a path or a node's answer cannot inject markup.
 *
 * @param {HTMLElement} container
 * @param {object} result
 */
function renderSealResult(container, result) {
    if (!result || result.error) {
        container.innerHTML = `
            <div class="result-card">
                <div class="result-head">
                    <div class="rok rbad">${window.ui.icon('warning', '', 18)}</div>
                    <h3>Sealing failed</h3>
                </div>
                <p class="result-lede" id="keyImportError"></p>
            </div>`;
        document.getElementById("keyImportError").textContent =
            String(result && result.error ? result.error : 'No parts were sealed');

        return;
    }

    const skipped = result.seatsWithoutAPart.length
        ? `<div class="note danger">${window.ui.icon('warning', '', 17)}
            <span>No part was found for seat ${seatList(result.seatsWithoutAPart)}. Those players join the
            ceremony without importing anything &mdash; check this is what you expect before you upload.</span>
           </div>`
        : '';

    container.innerHTML = `
        <div class="result-card safe">
            <div class="result-head">
                <div class="rok">${window.ui.icon('check', '', 18)}</div>
                <h3>Sealed ${result.sealedSeats.length} part(s)</h3>
            </div>
            <p class="result-lede">Each part was opened and immediately re-locked for the node that owns its seat.
                Nothing in the file below can be read by anyone else, including VAULTODY.</p>
            <div class="kv">
                <div class="kvl">${window.ui.icon('cube', '', 13)} <span id="keyImportSummary"></span></div>
                <div class="key-actions">
                    <button id="download-sealed" type="button" class="btn btn-ghost btn-sm"></button>
                </div>
            </div>
            ${skipped}
            <div class="note safe">
                ${window.ui.icon('checkCircle', '', 17)}
                <span>Upload this file in the VAULTODY Dashboard together with the 6-digit code it showed you when
                the import was started. Your vault then needs a fresh backup: the old package still opens the old
                key, but its parts are out of date.</span>
            </div>
        </div>`;

    document.getElementById("keyImportSummary").textContent =
        `${result.algorithm} · ${result.kind} · seats ${seatList(result.sealedSeats)} · ${result.fileName}`;

    const downloadButton = document.getElementById("download-sealed");
    downloadButton.innerHTML = `${window.ui.icon('download', '', 15)} Download sealed file`;
    downloadButton.addEventListener("click", () => {
        window.ui.downloadSecret(result.file, result.fileName);
    });
}

const keyImportResultContainer = document.getElementById("keyImportResultContainer");
document.getElementById("sealButton").addEventListener("click", () => {
    const privateKeyType = document.getElementById("privateKeySelect").value;
    const passwordElement = document.getElementById("password");
    if (passwordElement && !(passwordElement.value.length)) {
        alert("Password must not be empty!");
        return
    }

    keyImportResultContainer.innerHTML = window.ui.spinnerMarkup('Sealing each part to its node&hellip;');

    window.api
        .invoke("key-import:seal-parts", ticketPath, recoveryDataPath, rsaPath, privateKeyType, passwordElement?.value)
        .then(result => {
            renderSealResult(keyImportResultContainer, result);
        });
});

window.api.receive("status:key-import-ticket", (status) => {
    window.recovery.setPickerStatus("ticketFile", status);
});

window.api.receive("status:recovery-data", (status) => {
    window.recovery.setPickerStatus("recoveryDataFile", status);
});

window.api.receive("status:rsa-key", (status) => {
    window.recovery.setPickerStatus("rsaFile", status);
});

document.getElementById("privateKeySelect").addEventListener("change", () => {
    const selectValue = document.getElementById("privateKeySelect").value;

    switch (selectValue) {
        case "rawPemPrivateKey":
            renderPrivateKeyContainer(false);

            break;
        case "sjclEncryptedPrivateKey":
            renderPrivateKeyContainer(true);

            break;
    }
});

document.getElementById("key-import-note").innerHTML = window.ui.icon('checkCircle', '', 17)
    + ' <span>Your backup parts and your RSA key never leave this machine, and the whole private key is never'
    + ' assembled here &mdash; each part is opened and re-locked on its own, for one node only.</span>';
