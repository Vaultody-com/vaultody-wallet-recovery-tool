const generatePassword = document.getElementById('generate-new-password-button');
const generatePasswordInput = document.getElementById('generate-new-password-input');
const copyIconElement = document.getElementById('copy-icon');
const revealPasswordButton = document.getElementById('reveal-password');

generatePassword.innerHTML = `${window.ui.icon('refresh', '', 16)} Generate new password`;
copyIconElement.innerHTML = window.ui.icon('copy', '', 17);
window.ui.wireInputReveal(revealPasswordButton, generatePasswordInput);

document.getElementById('password-note').innerHTML = window.ui.icon('warning', '', 17)
    + ' <span>Store this password offline and separately from the RSA private key. If you lose it, the encrypted'
    + ' private key cannot be decrypted and your vault cannot be recovered.</span>';

generatePassword.addEventListener('click', async () => {
    generatePasswordInput.value = await window.api.invoke('utility:generate-password');
});

copyIconElement.addEventListener('click', () => {
    window.ui.copySecret(generatePasswordInput.value, 'Password');
});
