const PROVENANCE = [
    {icon: 'github', text: 'Open source'},
    {icon: 'scale', text: 'MIT License'},
    {icon: 'shield', text: 'No telemetry, no network'},
    {icon: 'cube', text: 'ECDSA + EdDSA'},
];

const LAUNCH_TOOLS = [
    {
        channel: 'screen:generate-password',
        icon: 'lock',
        title: 'Generate password',
        text: 'A strong random password to encrypt your RSA private key.',
        step: '1',
    },
    {
        channel: 'screen:rsa-key-generator',
        icon: 'key',
        title: 'Generate RSA key',
        text: 'Public key for the backup, encrypted private key for you.',
        step: '2',
    },
    {
        channel: 'screen:recover-self-provided',
        icon: 'shield',
        title: 'Recover wallet',
        text: 'Rebuild your master private key offline from your backup data.',
        step: '&crarr;',
        tone: 'danger',
    },
];

document.getElementById('home-mark').innerHTML = window.ui.icon('shield', '', 24);

document.getElementById('home-provenance').innerHTML = PROVENANCE
    .map(item => `<span class="prov">${window.ui.icon(item.icon, '', 13)} ${item.text}</span>`)
    .join('');

document.getElementById('home-launch').innerHTML = LAUNCH_TOOLS
    .map(tool => `
        <button class="tool${tool.tone ? ' ' + tool.tone : ''}" type="button" data-channel="${tool.channel}">
            <span class="ti">${window.ui.icon(tool.icon, '', 18)}</span>
            <span>
                <h4>${tool.title}</h4>
                <p>${tool.text}</p>
            </span>
            <span class="step-n">${tool.step}</span>
        </button>`)
    .join('');

document.querySelectorAll('.tool[data-channel]').forEach(tool => {
    tool.addEventListener('click', () => {
        window.api.send(tool.dataset.channel);
    });
});

document.getElementById('home-note').innerHTML = window.ui.icon('checkCircle', '', 17)
    + ' <span>Nothing you type or generate here leaves this machine. Passwords and private keys are never written to'
    + ' disk by this tool and are never transmitted &mdash; you choose where to store them.</span>';
