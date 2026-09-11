// The ticket downloaded from the Dashboard: the JSON form of the KeyImportTicket message.
// It names the seats and the node public key each seat's part must be sealed to, and carries
// no secrets - on a RECOVERY the chain code and the retired group public key come from the
// client's own backup package, because that is what every node re-reads from its own store.
//
// This is the shape gate only. Everything a ticket has to SAY for a ceremony to be able to
// run - a session id to derive the envelope key from, a public key for every seat, the
// declared key of a migration - is checked in KeyImportService, which can say which file to
// fix and why; a constraint here can only say that the file is not a ticket.
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
    },
    // Migration only: the key being brought in, echoed back from what was declared when the
    // import was initialized, one entry per algorithm. A recovery leaves it out entirely,
    // which is why nothing here is required - whether an entry has to be present is a
    // question about the ticket's kind, and that is KeyImportService's to answer.
    "externalKeys": {
        "type": "array",
        "objectArray": {
            "algorithm": {
                "presence": true,
                "type": "string",
                "inclusion": ["ecdsa", "eddsa"]
            },
            "chainCode": {
                "presence": true,
                "type": "string",
                "format": {
                    "pattern": "([0-9a-fA-F]{2})+"
                }
            },
            // Hex of the COMPRESSED group public key: 66 characters on secp256k1, 64 on
            // ed25519. The exact length per algorithm is checked where the algorithm is known.
            "publicKey": {
                "presence": true,
                "type": "string",
                "format": {
                    "pattern": "([0-9a-fA-F]{2})+"
                }
            }
        }
    }
}
