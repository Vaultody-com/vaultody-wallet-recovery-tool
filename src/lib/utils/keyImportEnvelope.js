'use strict';

const crypto = require("crypto");

/**
 * ENVELOPE v1 — seals ONE 32-byte polynomial point to ONE mpc-node.
 *
 * The offline tool never hands a share to a node in the clear. Each part is sealed under a key
 * only the recipient node can derive, and bound to a single ceremony, so a captured envelope
 * cannot be replayed into another import, re-pointed at another node, or opened as a node-to-node
 * ceremony frame.
 *
 *   ephemeral   fresh P-256 keypair per part, private half dropped straight after the ECDH
 *   shared      ECDH(ephemeralPriv, recipientNodePub) -> the 32-byte X coordinate
 *   KEK         HKDF-SHA256(ikm = shared, salt = nil, info = LABEL || hex(sessionId), len = 32)
 *   AAD         SHA-256 over the canonical binding (see computeBinding)
 *   ciphertext  AES-256-GCM(KEK, 12 random bytes, the 32-byte point, aad = AAD)
 *
 * The node-to-node channel derives its key with info = hex(sessionId) and NO label. The label is
 * the whole point: it stops a captured ceremony frame being opened as an envelope, and an
 * envelope being fed to the ceremony decryptor.
 *
 * Everything here is standard-library only — Electron 21 ships Node 16, which has
 * crypto.diffieHellman, crypto.hkdfSync and AES-256-GCM.
 */

const ENVELOPE_LABEL = "vaultody-mpc-key-import-v1";
const KEK_INFO_LABEL = `${ENVELOPE_LABEL}|`;

const POINT_BYTES_LENGTH = 32;
const KEK_BYTES_LENGTH = 32;
const GCM_NONCE_BYTES_LENGTH = 12;
const GCM_TAG_BYTES_LENGTH = 16;
const RECIPIENT_CURVE = "prime256v1";

const ALGORITHM = {
    ECDSA: "ecdsa",
    EDDSA: "eddsa",
};

/**
 * Length-prefixes one binding element: its byte length as a 4-byte big-endian unsigned integer,
 * then the bytes themselves. Without the prefix, "1" || "23" and "12" || "3" hash the same and
 * the binding stops binding.
 *
 * @param {Buffer} element
 * @return {Buffer}
 */
function lengthPrefixed(element) {
    const prefix = Buffer.allocUnsafe(4);
    prefix.writeUInt32BE(element.length, 0);

    return Buffer.concat([prefix, element]);
}

/**
 * @param {string} name
 * @param {Buffer|string} value
 * @return {Buffer}
 */
function toBuffer(name, value) {
    if (Buffer.isBuffer(value)) {
        return value;
    }
    if (typeof value === "string") {
        return Buffer.from(value, "hex");
    }

    throw new Error(`${name} must be a Buffer or a hex string`);
}

/**
 * @param {string} name
 * @param {number} value
 * @return {string}
 */
function toDecimalAscii(name, value) {
    if (!Number.isInteger(value) || value < 0) {
        throw new Error(`${name} must be a non-negative integer`);
    }

    return value.toString(10);
}

/**
 * The canonical binding: a length-prefixed concatenation in exactly this order, hashed with
 * SHA-256. The digest — not the concatenation — is what goes to GCM as additional data.
 *
 * The receiving node rebuilds this from its OWN state: importerIndex from its config, and
 * oldKeyId to load the retired key row from its own encrypted store for publicKey, chainCode and
 * oldThreshold. Only keyId, algorithm and newThreshold come from the request. A tampered or
 * replayed envelope therefore dies on the GCM tag, rather than on a comparison someone can skip.
 *
 * @param {{keyId: string, oldKeyId: string, algorithm: string, importerIndex: number,
 *          newThreshold: number, oldThreshold: number, publicKey: Buffer|string,
 *          chainCode: Buffer|string}} binding
 * @return {Buffer} the 32-byte SHA-256 digest
 */
function computeBinding(binding) {
    if (binding === null || typeof binding !== "object") {
        throw new Error("binding must be an object");
    }
    if (typeof binding.keyId !== "string" || binding.keyId.length === 0) {
        throw new Error("binding.keyId must be a non-empty string");
    }
    if (typeof binding.oldKeyId !== "string" || binding.oldKeyId.length === 0) {
        throw new Error("binding.oldKeyId must be a non-empty string");
    }
    if (binding.algorithm !== ALGORITHM.ECDSA && binding.algorithm !== ALGORITHM.EDDSA) {
        throw new Error(`binding.algorithm must be one of "${ALGORITHM.ECDSA}", "${ALGORITHM.EDDSA}"`);
    }

    const elements = [
        Buffer.from(ENVELOPE_LABEL, "ascii"),
        Buffer.from(binding.keyId, "ascii"),
        Buffer.from(binding.oldKeyId, "ascii"),
        Buffer.from(binding.algorithm, "ascii"),
        Buffer.from(toDecimalAscii("binding.importerIndex", binding.importerIndex), "ascii"),
        Buffer.from(toDecimalAscii("binding.newThreshold", binding.newThreshold), "ascii"),
        Buffer.from(toDecimalAscii("binding.oldThreshold", binding.oldThreshold), "ascii"),
        toBuffer("binding.publicKey", binding.publicKey),
        toBuffer("binding.chainCode", binding.chainCode),
    ];

    return crypto.createHash("sha256")
        .update(Buffer.concat(elements.map(lengthPrefixed)))
        .digest();
}

/**
 * Loads a recipient node's long-term public key. mpc-node carries it as base64 of the PKIX DER
 * (see config.DerivePublicKey), and it is EC P-256 — there is no RSA identity key in mpc-node.
 *
 * @param {string|Buffer|crypto.KeyObject} recipientPublicKey base64 PKIX DER, raw PKIX DER, or a KeyObject
 * @return {crypto.KeyObject}
 */
function loadRecipientPublicKey(recipientPublicKey) {
    let key;
    if (typeof recipientPublicKey === "object" && recipientPublicKey instanceof crypto.KeyObject) {
        key = recipientPublicKey;
    } else if (Buffer.isBuffer(recipientPublicKey)) {
        key = crypto.createPublicKey({key: recipientPublicKey, format: "der", type: "spki"});
    } else if (typeof recipientPublicKey === "string") {
        key = crypto.createPublicKey({
            key: Buffer.from(recipientPublicKey, "base64"),
            format: "der",
            type: "spki",
        });
    } else {
        throw new Error("recipientPublicKey must be a base64 PKIX DER string, a DER Buffer or a KeyObject");
    }

    if (key.type !== "public" || key.asymmetricKeyType !== "ec") {
        throw new Error("recipientPublicKey must be an EC public key");
    }
    if (key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve !== RECIPIENT_CURVE) {
        throw new Error(`recipientPublicKey must be on ${RECIPIENT_CURVE} (P-256)`);
    }

    return key;
}

/**
 * @param {crypto.KeyObject|string|Buffer|undefined} ephemeralPrivateKey
 * @return {{privateKey: crypto.KeyObject, publicKey: crypto.KeyObject}}
 */
function loadEphemeralKeyPair(ephemeralPrivateKey) {
    if (ephemeralPrivateKey === undefined || ephemeralPrivateKey === null) {
        return crypto.generateKeyPairSync("ec", {namedCurve: RECIPIENT_CURVE});
    }

    const privateKey = ephemeralPrivateKey instanceof crypto.KeyObject
        ? ephemeralPrivateKey
        : crypto.createPrivateKey(ephemeralPrivateKey);

    if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ec") {
        throw new Error("ephemeralPrivateKey must be an EC private key");
    }

    return {privateKey: privateKey, publicKey: crypto.createPublicKey(privateKey)};
}

/**
 * Derives the key-encryption key for one envelope.
 *
 * @param {crypto.KeyObject} ephemeralPrivateKey
 * @param {crypto.KeyObject} recipientPublicKey
 * @param {Buffer} sessionId
 * @return {{sharedSecret: Buffer, kek: Buffer}}
 */
function deriveKek(ephemeralPrivateKey, recipientPublicKey, sessionId) {
    const sharedSecret = crypto.diffieHellman({
        privateKey: ephemeralPrivateKey,
        publicKey: recipientPublicKey,
    });

    // Salt is nil, matching utils.DeriveSharedKey on the node side. Node's hkdfSync with a
    // zero-length salt and Go's hkdf.Key with a nil salt agree: RFC 5869 substitutes HashLen
    // zero bytes, and HMAC pads a short key with zeros to the block size either way.
    const info = Buffer.concat([
        Buffer.from(KEK_INFO_LABEL, "ascii"),
        Buffer.from(sessionId.toString("hex"), "ascii"),
    ]);

    const kek = Buffer.from(crypto.hkdfSync("sha256", sharedSecret, Buffer.alloc(0), info, KEK_BYTES_LENGTH));

    return {sharedSecret: sharedSecret, kek: kek};
}

/**
 * Seals one 32-byte polynomial point to one node.
 *
 * `ephemeralPrivateKey` and `nonce` exist ONLY so the checked-in test vectors are reproducible.
 * Real callers must omit both: a reused ephemeral key or a reused nonce under the same KEK
 * destroys GCM.
 *
 * @param {{point: Buffer|string, recipientPublicKey: string|Buffer|crypto.KeyObject,
 *          sessionId: Buffer|string, binding: object,
 *          ephemeralPrivateKey?: crypto.KeyObject|string|Buffer, nonce?: Buffer|string}} params
 * @return {{senderPublicKey: string, payload: string, bindingDigest: Buffer, nonce: Buffer,
 *           ciphertext: Buffer, authTag: Buffer}}
 */
function sealPoint(params) {
    if (params === null || typeof params !== "object") {
        throw new Error("sealPoint expects a parameters object");
    }

    const point = toBuffer("point", params.point);
    if (point.length !== POINT_BYTES_LENGTH) {
        throw new Error(`point must be exactly ${POINT_BYTES_LENGTH} bytes, got ${point.length}`);
    }

    const sessionId = toBuffer("sessionId", params.sessionId);
    if (sessionId.length === 0) {
        throw new Error("sessionId must not be empty");
    }

    const nonce = params.nonce === undefined || params.nonce === null
        ? crypto.randomBytes(GCM_NONCE_BYTES_LENGTH)
        : toBuffer("nonce", params.nonce);
    if (nonce.length !== GCM_NONCE_BYTES_LENGTH) {
        throw new Error(`nonce must be exactly ${GCM_NONCE_BYTES_LENGTH} bytes, got ${nonce.length}`);
    }

    const recipientPublicKey = loadRecipientPublicKey(params.recipientPublicKey);
    const bindingDigest = computeBinding(params.binding);

    const ephemeral = loadEphemeralKeyPair(params.ephemeralPrivateKey);
    const {kek} = deriveKek(ephemeral.privateKey, recipientPublicKey, sessionId);

    const cipher = crypto.createCipheriv("aes-256-gcm", kek, nonce, {authTagLength: GCM_TAG_BYTES_LENGTH});
    cipher.setAAD(bindingDigest);
    const ciphertext = Buffer.concat([cipher.update(point), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
        senderPublicKey: ephemeral.publicKey.export({type: "spki", format: "der"}).toString("base64"),
        payload: Buffer.concat([nonce, ciphertext, authTag]).toString("base64"),
        bindingDigest: bindingDigest,
        nonce: nonce,
        ciphertext: ciphertext,
        authTag: authTag,
    };
}

/**
 * Opens an envelope. The tool itself never needs this — the receiving node does — but the offline
 * side must be able to prove, without a node, that what it produced is openable and that every
 * bit of the binding is load-bearing.
 *
 * @param {{senderPublicKey: string, payload: string,
 *          recipientPrivateKey: crypto.KeyObject|string|Buffer,
 *          sessionId: Buffer|string, binding: object}} params
 * @return {Buffer} the 32-byte point
 */
function openEnvelope(params) {
    const sessionId = toBuffer("sessionId", params.sessionId);
    const senderPublicKey = crypto.createPublicKey({
        key: Buffer.from(params.senderPublicKey, "base64"),
        format: "der",
        type: "spki",
    });
    const recipientPrivateKey = params.recipientPrivateKey instanceof crypto.KeyObject
        ? params.recipientPrivateKey
        : crypto.createPrivateKey(params.recipientPrivateKey);

    const {kek} = deriveKek(recipientPrivateKey, senderPublicKey, sessionId);

    const sealed = Buffer.from(params.payload, "base64");
    if (sealed.length !== GCM_NONCE_BYTES_LENGTH + POINT_BYTES_LENGTH + GCM_TAG_BYTES_LENGTH) {
        throw new Error("payload is not a v1 envelope");
    }

    const nonce = sealed.subarray(0, GCM_NONCE_BYTES_LENGTH);
    const ciphertext = sealed.subarray(GCM_NONCE_BYTES_LENGTH, sealed.length - GCM_TAG_BYTES_LENGTH);
    const authTag = sealed.subarray(sealed.length - GCM_TAG_BYTES_LENGTH);

    const decipher = crypto.createDecipheriv("aes-256-gcm", kek, nonce, {authTagLength: GCM_TAG_BYTES_LENGTH});
    decipher.setAAD(computeBinding(params.binding));
    decipher.setAuthTag(authTag);

    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

module.exports = {
    ENVELOPE_LABEL: ENVELOPE_LABEL,
    KEK_INFO_LABEL: KEK_INFO_LABEL,
    ALGORITHM: ALGORITHM,
    POINT_BYTES_LENGTH: POINT_BYTES_LENGTH,
    GCM_NONCE_BYTES_LENGTH: GCM_NONCE_BYTES_LENGTH,
    GCM_TAG_BYTES_LENGTH: GCM_TAG_BYTES_LENGTH,
    computeBinding: computeBinding,
    deriveKek: deriveKek,
    sealPoint: sealPoint,
    openEnvelope: openEnvelope,
};
