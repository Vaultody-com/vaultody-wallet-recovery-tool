let ticketPath, rsaPath;
let recoveryDataPaths = [];

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
    title: 'Backup data files',
    sub: 'The .json files you downloaded when you backed up the vault \u2014 one per key on the ticket',
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

/**
 * @param {string} filePath
 * @return {string}
 */
function fileName(filePath) {
    return String(filePath).split(/[\\/]/).pop();
}

// A vault holding both an ecdsa and an eddsa key needs BOTH backup files in one run: the
// Dashboard refuses an upload that is short an algorithm, so there is no sealing one now and
// the other later. The dialog therefore takes a multiple selection, and each pick replaces the
// previous one.
const recoveryDataFileText = document.getElementById("recoveryDataFileText");
document.getElementById("recoveryDataFileButton").addEventListener("click", function () {
    window.api.invoke("file:recovery-data", true).then(result => {
        if (result.canceled) {
            return;
        }

        recoveryDataPaths = result.filePaths;

        const rejected = (result.invalidPaths || []).map(fileName);
        recoveryDataFileText.innerText = rejected.length
            ? `${result.filePaths.map(fileName).join(', ')} \u2014 not a backup data file: ${rejected.join(', ')}`
            : result.filePaths.join(', ');
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

    // A migration brings in a key VAULTODY has never held, so the chain code and the public key
    // were declared when the import was started rather than read from a node. The keys that were
    // sealed against are shown back, because they are the one thing on that path nobody else can
    // check for the client.
    const declaredKeys = result.keys.filter(key => key.declaredPublicKey);
    const declared = declaredKeys.length
        ? `<div class="note">${window.ui.icon('cube', '', 17)}
            <div>
                <span>Sealed against the key${declaredKeys.length > 1 ? 's' : ''} declared when this
                migration was started. If that is not the key you are bringing in, do not upload this
                file &mdash; start the import again.</span>
                <pre class="key-body" id="keyImportDeclaredKeys"></pre>
            </div>
           </div>`
        : '';

    container.innerHTML = `
        <div class="result-card safe">
            <div class="result-head">
                <div class="rok">${window.ui.icon('check', '', 18)}</div>
                <h3>Sealed ${result.sealedPartCount} part(s)</h3>
            </div>
            <p class="result-lede">Each part was opened and immediately re-locked for the node that owns its seat.
                Nothing in the file below can be read by anyone else, including VAULTODY.</p>
            <div class="kv">
                <div class="kvl">${window.ui.icon('cube', '', 13)} <span id="keyImportSummary"></span></div>
                <pre class="key-body" id="keyImportAlgorithms"></pre>
                <div class="key-actions">
                    <button id="download-sealed" type="button" class="btn btn-ghost btn-sm"></button>
                </div>
            </div>
            ${declared}
            <div class="note safe">
                ${window.ui.icon('checkCircle', '', 17)}
                <span>Upload this one file in the VAULTODY Dashboard together with the 6-digit code it showed you when
                the import was started &mdash; it carries every key on the ticket. Your vault then needs a fresh backup:
                the old packages still open the old keys, but their parts are out of date.</span>
            </div>
        </div>`;

    document.getElementById("keyImportSummary").textContent = `${result.kind} \u00b7 ${result.fileName}`;

    // One line per key on the ticket, so the client can see that BOTH of a two-algorithm vault's
    // keys went into the single file they are about to upload.
    document.getElementById("keyImportAlgorithms").textContent = result.keys
        .map(key => `${key.algorithm} \u00b7 key ${key.keyId} \u00b7 seats ${seatList(key.seats)}`)
        .join('\n');

    if (declaredKeys.length) {
        // textContent, not markup: the values come out of a downloaded file.
        document.getElementById("keyImportDeclaredKeys").textContent = declaredKeys
            .map(key => `${key.algorithm} \u00b7 ${key.declaredPublicKey}`)
            .join('\n');
    }

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
        .invoke("key-import:seal-parts", ticketPath, recoveryDataPaths, rsaPath, privateKeyType, passwordElement?.value)
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

// Said plainly, because "migration" reads like "bring in any key from anywhere" and it is not
// that: both kinds of import read the SAME VAULTODY backup format. A client holding a third
// party's export needs to know that before they start the ceremony in the Dashboard, not after
// the tool refuses their file.
document.getElementById("key-import-accepts").innerHTML = window.ui.icon('warning', '', 17)
    + ' <span><b>What this screen accepts:</b> VAULTODY backup data files &mdash; the .json your Dashboard'
    + ' produced when you backed the vault up, with one <span class="mono">shamir</span> part per player, each part'
    + ' carrying its player index and locked to your own RSA backup key. A <b>migration</b> uses exactly the same'
    + ' format; it only means the key being imported is one VAULTODY does not currently hold. A key exported from'
    + ' another custody provider is a different format and cannot be sealed here.</span>';

// THE CLIENT'S HALF OF THE EYE-CHECK. This tool seals VAULTODY's own seats to the keys compiled
// into it, never to the ones on the downloaded ticket, and a ticket that disagrees is refused. So
// the client is shown what this build actually carries: the Dashboard renders the same two keys
// beside the ticket, and the two readings have to agree. The Dashboard's copy is never the
// authority - this one is - which is precisely why this one has to be visible.
//
// A build with no keys in it cannot seal anything, and says so here, before any file is chosen.
window.api.invoke("key-import:pinned-node-keys").then((pinned) => {
    const container = document.getElementById("key-import-pinned");
    if (!pinned || !Array.isArray(pinned.seats)) {
        return;
    }

    if (!pinned.complete) {
        container.innerHTML = window.ui.icon('warning', '', 17)
            + ' <span id="keyImportPinnedMissing"><b>This build cannot seal anything.</b> It was packaged'
            + ' without VAULTODY&rsquo;s own node keys, so it has nothing to lock the VAULTODY seats of your'
            + ' ticket to, and it will not take them from the ticket. Get a signed release build of the'
            + ' VAULTODY Vault Recovery Tool before starting a key import.</span>';

        return;
    }

    container.classList.add('safe');
    container.innerHTML = window.ui.icon('checkCircle', '', 17)
        + ' <div><span><b>The VAULTODY keys this tool was built with.</b> Your parts for these seats are'
        + ' locked to exactly these keys &mdash; not to whatever the ticket says. Check they read the same as'
        + ' the ones your VAULTODY Dashboard shows next to the import; if they differ, stop and contact'
        + ' VAULTODY.</span><pre class="key-body" id="keyImportPinnedKeys"></pre></div>';

    // textContent, not markup: displayed values are never rendered as HTML on this screen.
    document.getElementById("keyImportPinnedKeys").textContent = pinned.seats
        .map(seat => `seat #${seat.index} · ${seat.name}\n  ${seat.fingerprint}\n  ${seat.publicKey}`)
        .join('\n');
});
