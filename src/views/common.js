// This file is required by the index.html file and will
// be executed in the renderer process for that window.
// No Node.js APIs are available in this process because
// `nodeIntegration` is turned off. Use `preload.js` to
// selectively enable features needed in the rendering
// process.

const SOURCE_CODE_URL = 'https://github.com/Vaultody-com/vaultody-wallet-recovery-tool';
const DASHBOARD_URL = 'https://app.vaultody.com/login';

const ICONS = {
    shield: '<path d="M12 3 4 6v6c0 5 3.5 7.5 8 9 4.5-1.5 8-4 8-9V6l-8-3Z"/><path d="m9 12 2 2 4-4"/>',
    home: '<path d="M3 10.5 12 3l9 7.5M5 9.5V20h14V9.5"/>',
    lock: '<rect x="3" y="10" width="18" height="11" rx="2"/><path d="M7 10V7a5 5 0 0 1 10 0v3"/>',
    key: '<circle cx="8" cy="8" r="5"/><path d="m12 12 8 8M17 17l3-3"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    checkCircle: '<path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="9"/>',
    warning: '<path d="M12 9v4m0 4h.01M10.3 3.9 2 18a2 2 0 0 0 1.7 3h16.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    eyeOff: '<path d="M3 3l18 18M10.6 10.7a3 3 0 0 0 4.2 4.2M6.1 6.3C3.8 7.9 2 12 2 12s3.5 7 10 7c2 0 3.7-.7 5.1-1.6M9.9 5.2A9.6 9.6 0 0 1 12 5c6.5 0 10 7 10 7a19 19 0 0 1-2.2 3"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    download: '<path d="M12 3v12m0 0-4-4m4 4 4-4M4 19h16"/>',
    refresh: '<path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/>',
    file: '<path d="M14 3v5h5M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    scale: '<path d="M4 7h16M4 12h16M4 17h10"/>',
    cube: '<path d="M3 8l9-5 9 5-9 5-9-5Z"/><path d="M3 8v8l9 5 9-5V8"/>',
    github: 'FILL:<path d="M12 .5a11.5 11.5 0 0 0-3.64 22.42c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.38-3.88-1.38-.53-1.33-1.3-1.69-1.3-1.69-1.06-.72.08-.71.08-.71 1.17.08 1.79 1.2 1.79 1.2 1.04 1.79 2.73 1.27 3.4.97.1-.75.4-1.27.73-1.56-2.56-.29-5.26-1.28-5.26-5.7 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.12 3.05.74.81 1.18 1.84 1.18 3.1 0 4.43-2.7 5.4-5.28 5.69.42.36.79 1.06.79 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z"/>',
};

const MASK_CHARACTER = '•';
const MASK_LENGTH = 44;

/**
 * @param {string} name
 * @param {string} className
 * @param {number} size
 * @return {string}
 */
function icon(name, className = '', size = 17) {
    const body = ICONS[name];
    const filled = body.startsWith('FILL:');
    const paint = filled
        ? 'fill="currentColor"'
        : 'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';

    return `<svg class="${className}" width="${size}" height="${size}" viewBox="0 0 24 24" ${paint} aria-hidden="true">`
        + (filled ? body.slice(5) : body)
        + '</svg>';
}

const NAV_GROUPS = [
    {
        label: 'Overview',
        items: [
            {id: 'home', channel: 'screen:home', icon: 'home', text: 'Home'},
        ],
    },
    {
        label: 'Back up a vault',
        items: [
            {id: 'generate-password', channel: 'screen:generate-password', icon: 'lock', text: 'Generate password', step: 1},
            {id: 'rsa-key-pairs', channel: 'screen:rsa-key-generator', icon: 'key', text: 'Generate RSA key', step: 2},
        ],
    },
    {
        label: 'Emergency',
        items: [
            {id: 'recovery', channel: 'screen:recover-self-provided', icon: 'shield', text: 'Recover vault'},
        ],
    },
];

/**
 * Renders the window chrome that must be identical on every screen: the
 * offline indicator, the source-code provenance and the intent-grouped nav.
 */
function renderChrome() {
    const activeNav = document.body.dataset.nav;

    document.getElementById('topbar').innerHTML = `
        <span class="tb-title">${icon('shield', '', 14)} VAULTODY Vault Recovery Tool</span>
        <span class="tb-right">
            <span class="offline-chip" id="offline-indicator" title="This tool never opens a network connection">
                <span class="dot"></span> Air-gapped &middot; offline
            </span>
            <button class="tb-icon" id="topbar-source" type="button" title="View source on GitHub" aria-label="View source on GitHub">
                ${icon('github', '', 16)}
            </button>
        </span>`;

    document.getElementById('rail').innerHTML = `
        <a class="brand" id="logo" href="#">
            <img alt="VAULTODY" src="../resources/images/logo-light.svg" />
        </a>
        ${NAV_GROUPS.map(group => `
            <div class="nav-group">
                <div class="nav-label">${group.label}</div>
                ${group.items.map(item => `
                    <button id="${item.id}" class="nav-item${item.id === activeNav ? ' active' : ''}"
                        type="button" data-channel="${item.channel}"
                        ${item.id === activeNav ? 'aria-current="page"' : ''}>
                        ${icon(item.icon, 'ic')}
                        <span>${item.text}</span>
                        ${item.step ? `<span class="step-n">${item.step}</span>` : ''}
                    </button>`).join('')}
            </div>`).join('')}
        <div class="rail-foot">
            <button class="src-btn" id="rail-source" type="button">
                ${icon('github', '', 15)} View source <span class="ext">&#8599;</span>
            </button>
            <div class="licence">MIT licensed &middot; no telemetry</div>
        </div>`;

    document.querySelectorAll('.nav-item').forEach(navItem => {
        navItem.addEventListener('click', () => {
            window.api.send(navItem.dataset.channel);
        });
    });

    document.getElementById('logo').addEventListener('click', () => {
        window.api.send('screen:home');
    });

    [document.getElementById('topbar-source'), document.getElementById('rail-source')].forEach(button => {
        button.addEventListener('click', () => {
            window.api.invoke('utility:open-link', (SOURCE_CODE_URL));
        });
    });
}

/**
 * Copies text to the clipboard, reporting an empty value instead of silently
 * copying nothing.
 *
 * @param {string} text
 * @param {string} label
 */
function copySecret(text, label) {
    if (text) {
        window.api.invoke('utility:clipboard-copy', (text));
        alert(`${label} copied successfully!`);
    } else {
        alert(`No ${label.toLowerCase()} to copy!`);
    }
}

/**
 * Downloads text as a file from the renderer.
 *
 * @param {string} text
 * @param {string} fileName
 */
function downloadSecret(text, fileName) {
    const blob = new Blob([text]);
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = fileName;
    link.click();
}

/**
 * Wires a reveal/hide toggle onto a password input. The input stays
 * type="password" until the toggle is pressed.
 *
 * @param {HTMLButtonElement} button
 * @param {HTMLInputElement} input
 */
function wireInputReveal(button, input) {
    button.innerHTML = icon('eye', '', 18);
    button.addEventListener('click', () => {
        const revealed = input.type === 'text';
        input.type = revealed ? 'password' : 'text';
        button.innerHTML = icon(revealed ? 'eye' : 'eyeOff', '', 18);
        button.classList.toggle('on', !revealed);
        button.title = revealed ? 'Reveal' : 'Hide';
    });
}

/**
 * Renders a secret so that the clear-text value is never written into the DOM
 * until the reader explicitly asks for it. The value lives in this closure,
 * not in an attribute.
 *
 * @param {HTMLElement} body
 * @param {HTMLButtonElement} button
 * @param {string} secret
 */
function wireSecretReveal(body, button, secret) {
    const mask = MASK_CHARACTER.repeat(MASK_LENGTH);
    let revealed = false;

    const paint = () => {
        body.textContent = revealed ? secret : mask;
        body.classList.toggle('masked', !revealed);
        body.setAttribute('aria-label', revealed ? 'Secret revealed' : 'Secret hidden');
        button.innerHTML = `${icon(revealed ? 'eyeOff' : 'eye', '', 15)} ${revealed ? 'Hide' : 'Reveal'}`;
    };

    button.addEventListener('click', () => {
        revealed = !revealed;
        paint();
    });

    paint();
}

/**
 * @param {string} message
 * @return {string}
 */
function spinnerMarkup(message) {
    return `<div class="spinner" role="status"><span class="ring"></span> ${message}</div>`;
}

window.ui = {
    icon,
    copySecret,
    downloadSecret,
    wireInputReveal,
    wireSecretReveal,
    spinnerMarkup,
    DASHBOARD_URL,
};

renderChrome();

document.querySelectorAll('.vaultody-wallets-link').forEach(function (vaultodyWalletsLink) {
    vaultodyWalletsLink.addEventListener('click', () => {
        window.api.invoke('utility:open-link', (DASHBOARD_URL));
    });
});
