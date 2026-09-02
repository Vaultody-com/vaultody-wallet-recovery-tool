const VAULTODY_PRIVATE_KEY_TYPE = "sjclEncryptedPrivateKey";

let recoveryDataPath, rsaPath;

document.getElementById("recoverButton").innerHTML =
    `${window.ui.icon('shield', '', 16)} Recover master xPriv`;

document.getElementById("recoveryDataFileField").innerHTML = window.recovery.pickerMarkup({
    id: 'recoveryDataFile',
    icon: 'file',
    title: 'Backup data file',
    sub: 'The .json you downloaded when you backed up the wallet',
});

document.getElementById("rsaFileField").innerHTML = window.recovery.pickerMarkup({
    id: 'rsaFile',
    icon: 'lock',
    title: 'RSA private key file',
    sub: 'The SJCL encrypted key file VAULTODY handed you',
});

document.getElementById("passwordField").innerHTML =
    window.recovery.passwordFieldMarkup('password', 'Private RSA key password');

const passwordElement = document.getElementById("password");
window.ui.wireInputReveal(document.getElementById("password-reveal"), passwordElement);

const recoveryDataFileText = document.getElementById("recoveryDataFileText");
document.getElementById("recoveryDataFileButton").addEventListener("click", () => {
    window.api.invoke("file:recovery-data").then(result => {
        if (!result.canceled) {
            recoveryDataFileText.innerText = result.filePaths[0];
            recoveryDataPath = result.filePaths[0];
        }
    });
});

const rsaFileText = document.getElementById("rsaFileText");
document.getElementById("rsaFileButton").addEventListener("click", () => {
    window.api.invoke("file:rsa-key", VAULTODY_PRIVATE_KEY_TYPE).then(result => {
        if (!result.canceled) {
            rsaFileText.innerText = result.filePaths[0];
            rsaPath = result.filePaths[0];
        }
    });
});

const recoveryResultContainer = document.getElementById("recoveryResultContainer");
document.getElementById("recoverButton").addEventListener("click", () => {
    if (!passwordElement.value.length) {
        alert("Password must not be empty!");
        return
    }

    recoveryResultContainer.innerHTML = window.ui.spinnerMarkup('Reconstructing the master key&hellip;');

    window.api.invoke("recover:recover-xpriv", recoveryDataPath, rsaPath, VAULTODY_PRIVATE_KEY_TYPE, passwordElement.value).then(result => {
        window.recovery.renderRecoveryResult(recoveryResultContainer, result);
    });
});

window.api.receive("status:rsa-key", (status) => {
    window.recovery.setPickerStatus("rsaFile", status);
});

window.api.receive("status:recovery-data", (status) => {
    window.recovery.setPickerStatus("recoveryDataFile", status);
});
