const {
    contextBridge,
    ipcRenderer
} = require("electron");

contextBridge.exposeInMainWorld(
    "api", {
        send: (channel, ...data) => {
            const validChannels = [
                "screen:recover-self-provided",
                "screen:recover-words",
                "screen:rsa",
                "screen:generate-password",
                "screen:rsa-key-generator",
                "screen:home",
            ];
            if (validChannels.includes(channel)) {
                ipcRenderer.send(channel, ...data);
            }
        },
        invoke: (channel, ...data) => {
            const validChannels = [
                "file:recovery-data",
                "file:rsa-key",
                "file:backup-package",
                "recover:recover-xpriv",
                "recover:recover-from-words",
                "utility:generate-rsa-key",
                "utility:generate-password",
                "utility:open-link",
                "utility:clipboard-copy",
            ];
            if (validChannels.includes(channel)) {
                return ipcRenderer.invoke(channel, ...data);
            }
        },
        receive: (channel, func) => {
            const validChannels = [
                "status:recovery-data",
                "status:rsa-key",
                "status:backup-package",
            ];
            if (validChannels.includes(channel)) {
                ipcRenderer.on(channel, (event, ...args) => func(...args));
            }
        }
    }
);