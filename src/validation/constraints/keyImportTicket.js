// The ticket downloaded from the Dashboard: the JSON form of the KeyImportTicket message.
// It names the seats and the node public key each seat's part must be sealed to, and carries
// no secrets - the chain code and the retired group public key come from the client's own
// backup package, never from here.
module.exports = {
    "vaultId": {
        "presence": true,
        "type": "string"
    },
    "kind": {
        "presence": true,
        "type": "string",
        "inclusion": ["recovery", "migration"]
    },
    "keyImportMetadata": {
        "presence": {
            "allowEmpty": false
        },
        "type": "array",
        "objectArray": {
            "algorithm": {
                "presence": true,
                "type": "string",
                "inclusion": ["ecdsa", "eddsa"]
            },
            // Hex, because the node hex-decodes the sessionId header before deriving the
            // envelope key over it.
            "sessionId": {
                "presence": true,
                "type": "string",
                "format": {
                    "pattern": "([0-9a-fA-F]{2})+"
                }
            },
            "keyId": {
                "presence": true,
                "type": "string"
            },
            "threshold": {
                "presence": true,
                "type": "number"
            },
            "players": {
                "presence": true,
                "type": "object"
            }
        }
    }
}
