// The ecies-p256-v1 backup package, as the embedded wallet e-mails it. Shape
// only; what each field means is checked by BackupPackageEntity.
const sealedPart = {
    "keyId": {
        "presence": true,
        "type": "string"
    },
    "index": {
        "presence": true,
        "type": "number"
    },
    "algorithm": {
        "presence": true,
        "type": "string"
    },
    "ephemeralPublicKey": {
        "presence": true,
        "type": "string"
    },
    "nonce": {
        "presence": true,
        "type": "string"
    },
    "ciphertext": {
        "presence": true,
        "type": "string"
    },
};

module.exports = {
    "version": {
        "presence": true,
        "type": "string"
    },
    "walletId": {
        "presence": true,
        "type": "string"
    },
    "recipientPublicKey": {
        "presence": true,
        "type": "string",
        "format": {
            "pattern": "^04[0-9a-fA-F]{128}$"
        }
    },
    "keys": {
        "presence": {
            "allowEmpty": false
        },
        "type": "array",
        "objectArray": {
            "keyId": {
                "presence": true,
                "type": "string",
            },
            "algorithm": {
                "presence": true,
                "type": "string",
            },
        },
    },
    "shares": {
        "presence": {
            "allowEmpty": false
        },
        "type": "array",
        "objectArray": sealedPart,
    },
    "chainCode": {
        "presence": true,
        "type": "object",
    },
};
