let recoveryDataPath, rsaPath;

const sourceToggle = document.getElementById("source-toggle");
sourceToggle.innerHTML = window.recovery.sourceToggleMarkup('self');
window.recovery.wireSourceToggle(sourceToggle);

document.getElementById("recoverButton").innerHTML =
    `${window.ui.icon('shield', '', 16)} Recover master xPriv`;

document.getElementById("recoveryDataFileField").innerHTML = window.recovery.pickerMarkup({
    id: 'recoveryDataFile',
    icon: 'file',
    title: 'Backup data file',
    sub: 'The .json you downloaded when you backed up the wallet',
});

const recoveryDataFileButton = document.getElementById("recoveryDataFileButton");
const recoveryDataFileText = document.getElementById("recoveryDataFileText");
recoveryDataFileButton.addEventListener("click", function () {
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
 * The password only exists for SJCL encrypted keys — a raw PEM key is not
 * password protected, so the field is not rendered at all.
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

const recoverButton = document.getElementById("recoverButton");
const recoveryResultContainer = document.getElementById("recoveryResultContainer");
recoverButton.addEventListener("click", () => {
    const privateKeyType = document.getElementById("privateKeySelect").value;
    const passwordElement = document.getElementById("password");
    if (passwordElement && !(passwordElement.value.length)) {
        alert("Password must not be empty!");
        return
    }

    recoveryResultContainer.innerHTML = window.ui.spinnerMarkup('Reconstructing the master key&hellip;');

    window.api.invoke("recover:recover-xpriv", recoveryDataPath, rsaPath, privateKeyType, passwordElement?.value).then(result => {
        window.recovery.renderRecoveryResult(recoveryResultContainer, result);
    });
});

window.api.receive("status:rsa-key", (status) => {
    window.recovery.setPickerStatus("rsaFile", status);
});

window.api.receive("status:recovery-data", (status) => {
    window.recovery.setPickerStatus("recoveryDataFile", status);
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
