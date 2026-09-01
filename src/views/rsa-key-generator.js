const generateRsaKeyButton = document.getElementById("generate-button");
const generateRsaResultContainer = document.getElementById("generate-rsa-result-container");
const passwordInput = document.getElementById("password");

generateRsaKeyButton.innerHTML = `${window.ui.icon('key', '', 16)} Generate RSA key pair`;
window.ui.wireInputReveal(document.getElementById("reveal-password"), passwordInput);

document.getElementById("rsa-note").innerHTML = window.ui.icon('warning', '', 17)
    + ' <span>Store the encrypted private key and its password in <b>separate</b> offline locations. Anyone holding'
    + ' both can recover your wallet.</span>';

generateRsaKeyButton.addEventListener('click', () => {
    const password = passwordInput.value;

    generateRsaResultContainer.innerHTML = window.ui.spinnerMarkup('Generating a 2048-bit RSA key pair&hellip;');

    window.api.invoke('utility:generate-rsa-key', (password))
        .then(result => {
            generateRsaResultContainer.innerHTML = `
                <div class="card">
                    <div class="key-card public">
                        <div class="key-head">
                            ${window.ui.icon('shield', '', 16)}
                            <span class="tag">Public key</span>
                            <span class="badge">Give to VAULTODY</span>
                        </div>
                        <pre class="key-body" id="generated-rsa-public-key-result"></pre>
                        <div class="key-actions">
                            <button id="copy-public-key" type="button" class="btn btn-ghost btn-sm"></button>
                        </div>
                    </div>
                    <div class="key-card private">
                        <div class="key-head">
                            ${window.ui.icon('lock', '', 16)}
                            <span class="tag">Encrypted private key</span>
                            <span class="badge">Keep secret</span>
                        </div>
                        <pre class="key-body masked" id="generated-rsa-private-key-result"></pre>
                        <div class="key-actions">
                            <button id="reveal-private-key" type="button" class="btn btn-ghost btn-sm"></button>
                            <button id="download-private-key" type="button" class="btn btn-ghost btn-sm"></button>
                        </div>
                    </div>
                </div>`;

            const publicKeyCopyButton = document.getElementById('copy-public-key');
            const privateKeyDownloadButton = document.getElementById('download-private-key');

            document.getElementById('generated-rsa-public-key-result').textContent = result.publicKey;
            publicKeyCopyButton.innerHTML = `${window.ui.icon('copy', '', 15)} Copy`;
            privateKeyDownloadButton.innerHTML = `${window.ui.icon('download', '', 15)} Download`;

            window.ui.wireSecretReveal(
                document.getElementById('generated-rsa-private-key-result'),
                document.getElementById('reveal-private-key'),
                result.privateKey
            );

            publicKeyCopyButton.addEventListener('click', function () {
                window.ui.copySecret(result.publicKey, 'Public key');
            });

            privateKeyDownloadButton.addEventListener('click', function () {
                if (result.privateKey) {
                    window.ui.downloadSecret(result.privateKey, 'private_key.json');
                } else {
                    alert('No private key was generated to be downloaded!');
                }
            });
        })
        .catch(function () {
            generateRsaResultContainer.innerHTML = `
                <div class="note danger">
                    ${window.ui.icon('warning', '', 17)}
                    <span>Password must not be empty and must have at least 8 characters, one upper case letter,
                    one number and one special symbol.</span>
                </div>`;
        });
});
