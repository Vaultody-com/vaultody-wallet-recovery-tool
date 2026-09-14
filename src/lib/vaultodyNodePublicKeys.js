'use strict';

const crypto = require('crypto');

/**
 * THE VAULTODY NODE PUBLIC KEYS THIS BUILD SEALS TO.
 *
 * The whole point of the offline tool is that the encrypting side cannot be redirected: whatever
 * produces the envelope decides the recipient from a value it ALREADY HOLDS, never from one an
 * online system hands it at run time. A ticket is downloaded from a web dashboard over a network,
 * by a client whose machine may already be the thing under attack. If the tool takes the
 * recipient's public key out of that file, then substituting the file substitutes the recipient,
 * and every part of the client's key is sealed to whoever swapped it. No signature on the ticket
 * fixes that - it just moves the question to who holds the signing key.
 *
 * So the two VAULTODY backend seats are pinned HERE, in the build, and the ticket's copy of them
 * is only ever COMPARED against this table. A disagreement is a hard refusal, never a fallback.
 *
 * WHY ONLY TWO SEATS ARE PINNED, WHICH IS NOT AN OVERSIGHT:
 *
 *   | Whose key                          | Where the tool gets it                              |
 *   |------------------------------------|-----------------------------------------------------|
 *   | The VAULTODY backend nodes (0, 1)  | pinned below; the ticket's copy is compared, never  |
 *   |                                    | trusted                                             |
 *   | The client's self-hosted co-signer | the ticket - the client generated that key when     |
 *   | (seat 3)                           | they stood their own node up, and can read it back  |
 *   |                                    | from that node                                      |
 *   | The client's handset (seat 2)      | the ticket - the key is generated on the device at  |
 *   |                                    | enrolment                                           |
 *
 * Only OUR keys can be pinned. A client's co-signer key and a handset key did not exist when this
 * build was cut - they are created per client, per device, long afterwards - so there is nothing
 * to compile in. For those seats the party that GENERATED the key is the party that vouches for
 * it, and the ticket is the correct carrier: a client who wants to check them reads them off
 * their own node and their own phone. The pinning replaces the VALUE at seats 0 and 1 only; every
 * seat keeps its entry in the ticket's players map, because that map is also how the tool learns
 * which seats are in play at all.
 *
 * FILLING THIS IN BEFORE A RELEASE BUILD. The table below ships EMPTY, and an empty table is a
 * hard refusal to seal anything - a tool that seals to a placeholder is worse than one that
 * refuses, because the client finds out after their key parts have been locked for a stranger.
 * The value each entry needs is the base64 PKIX (SubjectPublicKeyInfo) DER of the production mpc
 * node's P-256 identity public key - byte for byte the string vaults-manager puts in the
 * ticket's `players` map, which blockchain-signer reads from the `publicKey` field of its
 * VAULTODY_MPC_NODE_1 / VAULTODY_MPC_NODE_2 configuration. Those are held as deployment secrets;
 * see the release checklist in the README. Fill them in, verify each one against the node it
 * belongs to, and only then cut and sign the build.
 */
const PINNED_NODE_PUBLIC_KEYS = Object.freeze({
    // 0: '<base64 PKIX DER of production mpc node 0 identity public key>',
    // 1: '<base64 PKIX DER of production mpc node 1 identity public key>',
});

/**
 * THE STAGE (QA) TABLE. NOT FOR ANY BUILD A CLIENT RECEIVES.
 *
 * These are the identity public keys of VAULTODY's STAGE mpc nodes, which serve the QA
 * environments. They are here so a QA build can seal against the nodes a QA ceremony actually
 * runs on: the production table above must stay the production table, and a build that silently
 * fell back to whichever keys happened to be filled in would defeat the pinning it exists to
 * provide.
 *
 * These values are public keys and nothing else - the private halves never leave their nodes -
 * but a build carrying them can only seal for QA, so it must never be signed and shipped as the
 * client tool.
 *
 * Selection is EXPLICIT and one-way: set VAULTODY_NODE_KEY_SET=stage. Anything else, including
 * an unset variable, a typo, or an empty string, yields the production table. There is
 * deliberately no "whichever is populated" rule.
 */
const STAGE_NODE_PUBLIC_KEYS = Object.freeze({
    0: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2z4X/nbjFa00/5WSrdf2kFXwExY2C9D14RA9cEcgY2GhbvIkFsecS0ZXfBomIuDZVG55hS2VNYcGg6GuheRApg==',
    1: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOD4KQ76wdWnDT6a0PAk3vUH3kobSOb3x5AhiRw8C8hlSqwexx8ZDbfjXRR7KNqG9y1q2vJNgV0EGt7i9gLwBeg==',
});

/**
 * The key set this process seals with. Production unless stage is asked for by name.
 *
 * @return {Object<number,string>}
 */
function pinnedNodePublicKeysForBuild() {
    return process.env.VAULTODY_NODE_KEY_SET === 'stage'
        ? STAGE_NODE_PUBLIC_KEYS
        : PINNED_NODE_PUBLIC_KEYS;
}

/**
 * True when this process is sealing against STAGE nodes, so the caller can say so on screen. A
 * client must never be left guessing which deployment their key parts were sealed for.
 *
 * @return {boolean}
 */
function usingStageNodeKeys() {
    return process.env.VAULTODY_NODE_KEY_SET === 'stage';
}

/**
 * Who sits on which seat, in VAULTODY's numbering. The numbers are a deployment-wide convention,
 * not a per-vault one: a vault either has a seat or does not, but seat 3 is always the client's
 * own co-signer and seat 2 is always the client's handset.
 */
const SEAT = Object.freeze({
    VAULTODY_NODE_0: 0,
    VAULTODY_NODE_1: 1,
    MOBILE_DEVICE: 2,
    SERVER_COSIGNER: 3,
});

/**
 * The seats whose key this build is the authority on. Every other seat's key comes off the
 * ticket, by the table above.
 */
const PINNED_SEATS = Object.freeze([SEAT.VAULTODY_NODE_0, SEAT.VAULTODY_NODE_1]);

/**
 * What a seat is called on screen, so a refusal reads as something the client can act on rather
 * than a player number they have never heard of.
 */
const SEAT_NAMES = Object.freeze({
    [SEAT.VAULTODY_NODE_0]: 'VAULTODY node 0',
    [SEAT.VAULTODY_NODE_1]: 'VAULTODY node 1',
    [SEAT.MOBILE_DEVICE]: 'your VAULTODY mobile app',
    [SEAT.SERVER_COSIGNER]: 'your own co-signer node',
});

const RECIPIENT_CURVE = 'prime256v1';

/**
 * @param {number} index
 * @return {boolean}
 */
function isPinnedSeat(index) {
    return PINNED_SEATS.includes(index);
}

/**
 * @param {number} index
 * @return {string}
 */
function seatName(index) {
    return SEAT_NAMES[index] || `seat #${index}`;
}

/**
 * The canonical DER of a node public key, or null when the value is not one this tool could seal
 * to at all.
 *
 * Canonical, not the string as written: the same key can reach the tool base64'd with or without
 * padding or with whitespace in it, and two spellings of one key must not read as two keys. The
 * key is re-exported through node's own parser, which is also what the envelope will do with it,
 * so anything that gets past here can actually be sealed to.
 *
 * @param {string} value base64 PKIX DER
 * @return {Buffer|null}
 */
function canonicalPublicKey(value) {
    if (typeof value !== 'string' || value.trim().length === 0) {
        return null;
    }

    try {
        const key = crypto.createPublicKey({
            key: Buffer.from(value.trim(), 'base64'),
            format: 'der',
            type: 'spki',
        });

        if (key.asymmetricKeyType !== 'ec'
            || key.asymmetricKeyDetails?.namedCurve !== RECIPIENT_CURVE
        ) {
            return null;
        }

        return key.export({type: 'spki', format: 'der'});
    } catch (e) {
        return null;
    }
}

/**
 * A short, readable name for one public key: the first 8 bytes of its SHA-256, which is the same
 * digest mpc-node names a peer's queue by. Short enough to read out over the phone to VAULTODY
 * support, and it is a name for a key, never a substitute for comparing the key itself.
 *
 * @param {Buffer} der canonical DER, as returned by canonicalPublicKey
 * @return {string}
 */
function fingerprint(der) {
    return crypto.createHash('sha256')
        .update(der)
        .digest('hex')
        .slice(0, 16)
        .toUpperCase()
        .replace(/(.{4})(?=.)/g, '$1-');
}

/**
 * @param {Buffer|null} left
 * @param {Buffer|null} right
 * @return {boolean}
 */
function samePublicKey(left, right) {
    return left !== null && right !== null && left.equals(right);
}

module.exports = {
    PINNED_NODE_PUBLIC_KEYS,
    PINNED_SEATS,
    STAGE_NODE_PUBLIC_KEYS,
    SEAT,
    canonicalPublicKey,
    fingerprint,
    isPinnedSeat,
    pinnedNodePublicKeysForBuild,
    samePublicKey,
    seatName,
    usingStageNodeKeys,
};
