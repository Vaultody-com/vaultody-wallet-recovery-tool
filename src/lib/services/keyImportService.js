'use strict';

const sjcl = require('sjcl');
const envelope = require('../utils/keyImportEnvelope');
const nodeKeys = require('../vaultodyNodePublicKeys');
const privateKeyTypeEnum = require('../enumerations/privateKeyType');
const sharingTypeEnum = require('../enumerations/sharingType');
const {CURVE} = require('../enumerations/curve');
const {IMPORTABLE_SCHEMES, MPC_CUSTODY_SCHEME, schemeOfRoster} = require('../enumerations/mpcCustodyScheme');

/**
 * Which algorithm name a package's curve travels under on the ticket, on the node's
 * /v1/keys/import request and inside the envelope binding.
 */
const ALGORITHM_BY_CURVE = {
    [CURVE.SECP256K1]: envelope.ALGORITHM.ECDSA,
    [CURVE.ED25519]: envelope.ALGORITHM.EDDSA,
};

const ALGORITHMS = [envelope.ALGORITHM.ECDSA, envelope.ALGORITHM.EDDSA];

/**
 * How long the hex of a compressed group public key is, per algorithm: twice the byte length
 * the binding is defined over, which is also the cap the node's api puts on the field.
 */
const EXTERNAL_PUBLIC_KEY_HEX_LENGTH = {
    [envelope.ALGORITHM.ECDSA]: envelope.RETIRED_PUBLIC_KEY_BYTES_LENGTH[envelope.ALGORITHM.ECDSA] * 2,
    [envelope.ALGORITHM.EDDSA]: envelope.RETIRED_PUBLIC_KEY_BYTES_LENGTH[envelope.ALGORITHM.EDDSA] * 2,
};

/**
 * THE ONE INPUT FORMAT THIS TOOL SEALS FROM, named in every refusal that is about the format.
 *
 * It is deliberately narrow, and "migration" does not widen it - see the class comment.
 */
const ACCEPTED_PACKAGE = 'a VAULTODY backup data file - the .json your Dashboard produced when '
    + 'you backed the vault up, holding a shamir sharing whose parts each name their player '
    + 'index and are RSA-sealed to your own backup key';

const HEX = /^([0-9a-fA-F]{2})+$/;

/**
 * Seals the key parts of a VAULTODY backup package to the nodes named on a key-import ticket.
 *
 * WHAT THIS ACCEPTS. One VAULTODY backup data file per algorithm the ticket lists, and nothing
 * else. Concretely, every input package must be:
 *
 *   - a VAULTODY backup package, version 1, 2 or 3, of the shape recoveryData constraints check;
 *   - a `shamir` sharing, because Lagrange interpolation of the imported points is what rebuilds
 *     the group secret inside the ceremony;
 *   - carrying a part for every seat the ticket names, each part labelled with ITS OWN player
 *     index in VAULTODY's numbering - not its position in the array;
 *   - with every part, and the master chain code, RSA-sealed to the backup key pair the client
 *     generated in this tool.
 *
 * WHAT "MIGRATION" MEANS HERE, WHICH IS LESS THAN THE WORD PROMISES. The two kinds differ only
 * in where the two bound values that describe the key come from, never in the format of the
 * package they come out of:
 *
 *   recovery   VAULTODY still holds a row for the retired key, and every node re-reads the
 *              public key and chain code from it.
 *   migration  VAULTODY holds no such row - the key was generated on a deployment this one has
 *              never talked to - so both values were declared when the import was initialized
 *              and are echoed back on the ticket.
 *
 * So a migration today is "import a VAULTODY-format backup package of a key THIS deployment does
 * not hold", which in practice means a key that came out of another VAULTODY deployment, or out
 * of this tool's own backup format. A third-party custodian's export is NOT accepted, and is
 * refused by name rather than half-read: see "What a genuinely external key would additionally
 * require" in the README for what that path would still need.
 *
 * WHO THE PARTS ARE SEALED TO, AND WHERE THAT ANSWER COMES FROM. The ticket is a file downloaded
 * over a network from a web dashboard, so it is exactly the "value an online system supplies at
 * run time" that this tool must not take its recipient from. VAULTODY's own two backend seats are
 * therefore PINNED in the build (src/lib/vaultodyNodePublicKeys.js) and the ticket's copy of them
 * is only compared against the pinned pair; a disagreement refuses the run. The client's own
 * seats - their handset and their self-hosted co-signer - keep coming off the ticket, because
 * their keys are generated per client and per device long after this build was cut, and the party
 * that generated a key is the party who can vouch for it. The full table is in that file.
 *
 * WHICH VAULTS CAN BE IMPORTED AT ALL. mobile_cosigner and server_cosigner. full_custody and
 * hybrid are refused by name here rather than upstream an hour later - see
 * src/lib/enumerations/mpcCustodyScheme.js.
 */
class KeyImportService {

    /**
     * @param {object} pinnedNodePublicKeys VAULTODY's own node public keys, seat index -> base64
     *        PKIX DER. THIS IS A BUILD-TIME VALUE. The default is the table compiled into this
     *        build, and production constructs the service with no argument at all
     *        (src/services/keyImport.js), so no ticket, no file, no IPC message and no
     *        environment variable can reach it. The parameter exists so the suite can prove the
     *        comparison in both directions against keys it generated itself.
     */
    constructor(pinnedNodePublicKeys = nodeKeys.PINNED_NODE_PUBLIC_KEYS) {
        this.pinnedNodePublicKeys = this._readPinnedKeys(pinnedNodePublicKeys);
    }

    /**
     * The pinned table as canonical DER, with anything unreadable left OUT rather than passed on.
     * A seat missing here is a seat this build cannot seal to, and that is refused at seal time
     * in words a client can act on - which is also what a fat-fingered entry has to look like,
     * because a key that cannot be parsed is not a key.
     *
     * @param {object} pinnedNodePublicKeys
     * @return {Map<number, Buffer>}
     * @private
     */
    _readPinnedKeys(pinnedNodePublicKeys) {
        const pinned = new Map();
        for (const [seat, value] of Object.entries(pinnedNodePublicKeys || {})) {
            const der = nodeKeys.canonicalPublicKey(value);
            if (der !== null) {
                pinned.set(Number(seat), der);
            }
        }

        return pinned;
    }

    /**
     * Opens every key part the ticket asks for - for EVERY algorithm it lists - and re-seals it,
     * one at a time, to the node that owns that seat.
     *
     * ONE CALL COVERS THE WHOLE TICKET, ON PURPOSE. vaults-manager's completeKeyImport walks
     * every algorithm on the ticket and refuses the upload if any one of them is short a seat,
     * so a file holding a single algorithm of a two-algorithm vault can never be accepted. The
     * client therefore hands in every backup package at once and gets ONE sealed file back.
     *
     * THIS IS ALSO THE WHOLE CEREMONY-SIDE OPERATION, ON PURPOSE. The parts are decrypted and
     * re-sealed inside this one call: no plaintext point is returned, stored, or handed across
     * an IPC boundary, and recoverPrivateKey is never called, so the group secret is not formed
     * even for an instant. What comes back is ciphertext addressed to the nodes plus the public
     * bookkeeping the client needs to see.
     *
     * The ticket and every package are checked in full BEFORE the RSA key is opened and before
     * anything is sealed. Every refusal below is a ceremony that cannot succeed, and the client
     * finds out here, in a sentence naming the file to fix, rather than from a node an hour
     * later.
     *
     * @param {object} ticket the key-import ticket downloaded from the Dashboard
     * @param {RecoveryDataEntity[]|RecoveryDataEntity} recoveryData the client's backup packages,
     *        one per algorithm the ticket lists
     * @param {Buffer} privateKeyBuffer the client's RSA private key file, as read from disk
     * @param {string} privateKeyType
     * @param {string|null} password
     * @return {{vaultId: string, kind: string,
     *           keys: {algorithm: string, keyId: string, declaredPublicKey: string|null,
     *           seats: number[], scheme: string}[],
     *           sealedParts: {algorithm: string, index: number, senderPublicKey: string,
     *           payload: string}[]}}
     */
    sealKeyParts(ticket, recoveryData, privateKeyBuffer, privateKeyType, password = null) {
        const packages = Array.isArray(recoveryData) ? recoveryData : [recoveryData];
        const kind = this._readKind(ticket);
        const isRecovery = kind === envelope.KIND.RECOVERY;

        // Everything that can refuse the run happens here, before a single byte is decrypted.
        const sessions = this._sessions(ticket, isRecovery);
        const packagesByAlgorithm = this._indexPackagesByAlgorithm(packages, sessions);
        const plan = sessions.map(metadata => this._planAlgorithm(ticket, metadata, packagesByAlgorithm, isRecovery));

        let rsaPrivateKey;
        try {
            rsaPrivateKey = privateKeyType.includes(privateKeyTypeEnum.SJCL_ENCRYPTED)
                ? sjcl.decrypt(password, privateKeyBuffer.toString())
                : privateKeyBuffer.toString();
        } catch (e) {
            throw new Error("Invalid password!");
        }

        const keys = [];
        const sealedParts = [];
        for (const step of plan) {
            const parts = this._sealAlgorithm(step, rsaPrivateKey, kind);

            keys.push({
                algorithm: step.algorithm,
                keyId: step.metadata.keyId,
                // Public, and worth showing: on a migration this is the key the nodes will be
                // told they imported, so the client can read it back against the key they meant
                // to bring.
                declaredPublicKey: step.externalKey === null ? null : step.externalKey.publicKey,
                seats: step.seats,
                scheme: step.scheme,
            });
            sealedParts.push(...parts);
        }

        return {
            vaultId: ticket.vaultId,
            kind: kind,
            keys: keys,
            sealedParts: sealedParts,
        };
    }

    /**
     * What this build pins, so the screen can show it and the client can do the eye-check the
     * ceremony asks of them: the Dashboard renders its own copy of these same keys, and the two
     * have to read the same. The Dashboard's copy is never the authority - this one is - which is
     * exactly why both have to be visible.
     *
     * An incomplete answer is not a detail: it says this build cannot seal at all, and the screen
     * says so before the client chooses a single file.
     *
     * @return {{complete: boolean, seats: {index: number, name: string, publicKey: string|null,
     *           fingerprint: string|null}[]}}
     */
    pinnedNodeKeys() {
        const seats = nodeKeys.PINNED_SEATS.map(index => {
            const der = this.pinnedNodePublicKeys.get(index);

            return {
                index: index,
                name: nodeKeys.seatName(index),
                publicKey: der === undefined ? null : der.toString('base64'),
                fingerprint: der === undefined ? null : nodeKeys.fingerprint(der),
            };
        });

        return {
            complete: seats.every(seat => seat.publicKey !== null),
            seats: seats,
        };
    }

    /**
     * Seals one algorithm's parts. Every check that could refuse this algorithm has already run
     * in _planAlgorithm, so from here on the only thing that can fail is the client's RSA key
     * failing to open a part.
     *
     * @param {object} step
     * @param {string} rsaPrivateKey
     * @param {string} kind
     * @return {{algorithm: string, index: number, senderPublicKey: string, payload: string}[]}
     * @private
     */
    _sealAlgorithm(step, rsaPrivateKey, kind) {
        const {metadata, algorithm, seats, recipients, recoveryData, externalKey} = step;
        const isRecovery = kind === envelope.KIND.RECOVERY;

        // Where the two bound values that describe the key itself come from, and they come from
        // different places per kind:
        //
        //   recovery   both are the package's. Each node re-reads them from its OWN stored row
        //              for the retired key - the one check in the path that is not being asked
        //              of the same caller who supplies the parts - and the envelope dies on the
        //              GCM tag if what the package holds disagrees.
        //   migration  there is no such row to read, so the values were declared once when the
        //              import was initialized and echoed back on the ticket. The node binds the
        //              chain code it was handed, so the tool must bind the SAME one, and the
        //              retired public key is not part of a migration binding at all.
        const publicKey = isRecovery ? recoveryData.getCompressedPublicKey() : undefined;
        const oldThreshold = isRecovery ? metadata.oldThreshold : 0;
        const chainCode = isRecovery
            ? recoveryData.recoverChainCode(rsaPrivateKey)
            : externalKey.chainCode;

        const sealedParts = [];
        for (const index of seats) {
            const point = this._openKeyPart(recoveryData, index, rsaPrivateKey, algorithm);

            let sealed;
            try {
                sealed = envelope.sealPoint({
                    point: point,
                    // The recipient the PLAN resolved, never `metadata.players[index]`: for
                    // VAULTODY's own seats that is the key compiled into this build, and the
                    // ticket's copy of it has already been compared and agreed with.
                    recipientPublicKey: recipients.get(index),
                    sessionId: metadata.sessionId,
                    binding: {
                        kind: kind,
                        keyId: metadata.keyId,
                        oldKeyId: isRecovery ? metadata.oldKeyId : undefined,
                        algorithm: algorithm,
                        importerIndex: index,
                        newThreshold: metadata.threshold,
                        oldThreshold: oldThreshold,
                        publicKey: publicKey,
                        chainCode: chainCode,
                    },
                });
            } finally {
                // The point stops existing here whatever happened: it is the one value in this
                // function that must never outlive the seal.
                point.fill(0);
            }

            sealedParts.push({
                algorithm: algorithm,
                index: index,
                senderPublicKey: sealed.senderPublicKey,
                payload: sealed.payload,
            });
        }

        return sealedParts;
    }

    /**
     * The kind decides what the node is required to hold and is the first element of the
     * binding, so an unrecognised one cannot be treated as "probably a migration" - that is the
     * path with no anchor to check against.
     *
     * @param {object} ticket
     * @return {string}
     * @private
     */
    _readKind(ticket) {
        const kind = ticket.kind;
        if (kind !== envelope.KIND.RECOVERY && kind !== envelope.KIND.MIGRATION) {
            throw new Error(
                `The ticket says this import is "${kind}", which this tool does not know how to `
                + `seal for. Download the ticket again from the Dashboard - a valid one says `
                + `either "${envelope.KIND.RECOVERY}" or "${envelope.KIND.MIGRATION}".`
            );
        }

        return kind;
    }

    /**
     * Every algorithm the ticket lists, checked in full and carrying the ticket's kind, because
     * that is what the binding pins.
     *
     * ALL of them are sealed in one run: the upload is refused unless every algorithm on the
     * ticket has every one of its seats filled, so there is no such thing as sealing one of them
     * now and the other later.
     *
     * @param {object} ticket
     * @param {boolean} isRecovery
     * @return {object[]}
     * @private
     */
    _sessions(ticket, isRecovery) {
        const sessions = Array.isArray(ticket.keyImportMetadata) ? ticket.keyImportMetadata : [];
        if (sessions.length === 0) {
            throw new Error(
                `The ticket names no key to import. Download the ticket again from the Dashboard.`
            );
        }

        const seen = new Set();
        for (const metadata of sessions) {
            const algorithm = metadata.algorithm;
            if (!ALGORITHMS.includes(algorithm)) {
                throw new Error(
                    `The ticket asks for a "${algorithm}" key, which this tool cannot seal for. `
                    + `It seals ${ALGORITHMS.join(' and ')} keys. Download the ticket again from `
                    + `the Dashboard.`
                );
            }

            if (seen.has(algorithm)) {
                throw new Error(
                    `The ticket lists the ${algorithm} key twice, so there is no single set of `
                    + `seats to seal for it. Download the ticket again from the Dashboard.`
                );
            }

            seen.add(algorithm);
            this._assertSessionIsComplete(metadata, algorithm, isRecovery);
        }

        return sessions;
    }

    /**
     * @param {object} metadata
     * @param {string} algorithm
     * @param {boolean} isRecovery
     * @private
     */
    _assertSessionIsComplete(metadata, algorithm, isRecovery) {
        // The envelope key is HKDF over the ECDH secret with the session id in the info
        // parameter, so a part sealed without it - or against a different one - simply does not
        // open at the node. There is nothing to fall back on and nothing to invent here.
        if (typeof metadata.sessionId !== 'string' || !HEX.test(metadata.sessionId)) {
            throw new Error(
                `The ${algorithm} session of the ticket carries no sessionId, so its parts cannot `
                + `be sealed to anything. Start the import again in the Dashboard and download `
                + `the new ticket.`
            );
        }

        if (typeof metadata.keyId !== 'string' || metadata.keyId.length === 0) {
            throw new Error(
                `The ${algorithm} session of the ticket names no key to import into. Download the `
                + `ticket again from the Dashboard.`
            );
        }

        if (!Number.isInteger(metadata.threshold) || metadata.threshold < 1) {
            throw new Error(
                `The ${algorithm} session of the ticket declares no threshold for the new key. `
                + `Download the ticket again from the Dashboard.`
            );
        }

        if (isRecovery) {
            if (typeof metadata.oldKeyId !== 'string' || metadata.oldKeyId.length === 0) {
                throw new Error(
                    `The ${algorithm} session of the ticket does not say which key is being `
                    + `restored. Download the ticket again from the Dashboard.`
                );
            }

            // 0 is what every row the pre-fix importer wrote carries, and it means "unknown",
            // never "matches"; a node refuses the import on it.
            if (!Number.isInteger(metadata.oldThreshold) || metadata.oldThreshold < 1) {
                throw new Error(
                    `The ${algorithm} session of the ticket does not say how many parts the `
                    + `retired key needed. Download the ticket again from the Dashboard.`
                );
            }
        }
    }

    /**
     * Files the backup packages the client gave by the algorithm each one holds, and refuses the
     * run unless that set is EXACTLY the set of algorithms the ticket lists.
     *
     * A package short of the ticket cannot produce an upload the Dashboard will take; a package
     * the ticket did not ask for means the client picked a file from another vault, and sealing
     * around it silently would leave them believing it went in.
     *
     * @param {RecoveryDataEntity[]} packages
     * @param {object[]} sessions
     * @return {Map<string, RecoveryDataEntity>}
     * @private
     */
    _indexPackagesByAlgorithm(packages, sessions) {
        if (packages.length === 0) {
            throw new Error(`No backup data file was given. This tool seals from ${ACCEPTED_PACKAGE}.`);
        }

        const byAlgorithm = new Map();
        for (const recoveryData of packages) {
            const curve = recoveryData.getCurve();
            const algorithm = ALGORITHM_BY_CURVE[curve];
            if (!algorithm) {
                throw new Error(
                    `One of the backup data files is on a curve this tool cannot seal from: `
                    + `"${curve}". It seals ${ALGORITHMS.join(' and ')} keys, from `
                    + `${ACCEPTED_PACKAGE}.`
                );
            }

            // Lagrange interpolation of the imported points is what rebuilds the group secret
            // inside the ceremony. An additive or multiplicative package's parts are not
            // polynomial points, so importing them would not fail - it would silently rebuild a
            // different key.
            if (recoveryData.getSharingType() !== sharingTypeEnum.SHAMIR) {
                throw new Error(
                    `The ${algorithm} backup data file is a "${recoveryData.getSharingType()}" `
                    + `sharing, and only a ${sharingTypeEnum.SHAMIR} one can be imported. This `
                    + `tool seals from ${ACCEPTED_PACKAGE}.`
                );
            }

            if (byAlgorithm.has(algorithm)) {
                throw new Error(
                    `Two of the backup data files hold an ${algorithm} key. Give exactly one `
                    + `backup file per algorithm the ticket lists.`
                );
            }

            byAlgorithm.set(algorithm, recoveryData);
        }

        const wanted = sessions.map(metadata => metadata.algorithm);
        const missing = wanted.filter(algorithm => !byAlgorithm.has(algorithm));
        if (missing.length) {
            throw new Error(
                `No backup data file was given for ${this._list(missing)}. This ticket imports `
                + `the ${this._list(wanted)} key${wanted.length === 1 ? '' : 's'} of the vault, `
                + `and every one of them has to be sealed in the same run - the Dashboard `
                + `refuses an upload that is short an algorithm - so choose the `
                + `${this._list(missing)} backup data file as well and seal again. This tool `
                + `seals from ${ACCEPTED_PACKAGE}.`
            );
        }

        const surplus = [...byAlgorithm.keys()].filter(algorithm => !wanted.includes(algorithm));
        if (surplus.length) {
            throw new Error(
                `The backup data files given include ${this._list(surplus)}, but this ticket `
                + `imports only the ${this._list(wanted)} key of the vault. Remove the `
                + `${this._list(surplus)} file, or check that every file is a backup of the vault `
                + `being imported.`
            );
        }

        return byAlgorithm;
    }

    /**
     * Everything one algorithm needs in order to be sealed, resolved and checked before any
     * secret is opened.
     *
     * @param {object} ticket
     * @param {object} metadata
     * @param {Map<string, RecoveryDataEntity>} packagesByAlgorithm
     * @param {boolean} isRecovery
     * @return {{metadata: object, algorithm: string, seats: number[], scheme: string,
     *           recipients: Map<number, Buffer>, recoveryData: RecoveryDataEntity,
     *           externalKey: object|null}}
     * @private
     */
    _planAlgorithm(ticket, metadata, packagesByAlgorithm, isRecovery) {
        const algorithm = metadata.algorithm;
        const recoveryData = packagesByAlgorithm.get(algorithm);
        const seats = this._seats(metadata, algorithm);
        const scheme = this._readScheme(seats, algorithm);
        const recipients = this._recipients(metadata, seats, algorithm);

        this._assertPackageCoversTheTicket(recoveryData, seats, isRecovery, metadata.oldThreshold, algorithm);

        return {
            metadata: metadata,
            algorithm: algorithm,
            seats: seats,
            scheme: scheme,
            recipients: recipients,
            recoveryData: recoveryData,
            externalKey: isRecovery ? null : this._findExternalKey(ticket, algorithm, recoveryData),
        };
    }

    /**
     * Which custody scheme the ticket's seats describe, refusing the two that v1 does not cover.
     *
     * The ticket carries a roster, not a scheme name, and that is enough: the roster is built in
     * exactly one place upstream, so it is the scheme's own footprint. See
     * src/lib/enumerations/mpcCustodyScheme.js for the table and for why hybrid needs an explicit
     * refusal rather than falling out of the code.
     *
     * @param {number[]} seats
     * @param {string} algorithm
     * @return {string}
     * @private
     */
    _readScheme(seats, algorithm) {
        const scheme = schemeOfRoster(seats);
        if (IMPORTABLE_SCHEMES.includes(scheme)) {
            return scheme;
        }

        if (scheme === MPC_CUSTODY_SCHEME.FULL_CUSTODY) {
            throw new Error(
                `This ticket is for a vault VAULTODY holds on its own: its ${algorithm} session `
                + `seats only VAULTODY's own nodes (${this._seatNameList(seats)}), which is the `
                + `"${MPC_CUSTODY_SCHEME.FULL_CUSTODY}" scheme. Key import covers the vaults you `
                + `co-sign - with your VAULTODY mobile app, or with your own co-signer node - and `
                + `not this one. Nothing has been sealed. Contact VAULTODY rather than going any `
                + `further; a ticket like this should not have been issued.`
            );
        }

        if (scheme === MPC_CUSTODY_SCHEME.HYBRID) {
            throw new Error(
                `This ticket seats BOTH your VAULTODY mobile app and your own co-signer node - `
                + `the "${MPC_CUSTODY_SCHEME.HYBRID}" scheme - and key import does not cover it. `
                + `It covers a vault co-signed by your mobile app, or one co-signed by your own `
                + `node, but not one that uses both. Nothing has been sealed. Contact VAULTODY `
                + `rather than going any further; a ticket like this should not have been issued.`
            );
        }

        throw new Error(
            `The ${algorithm} session of this ticket seats ${this._seatList(seats)}, which is not `
            + `a set of players VAULTODY issues for a key import. The imports this tool seals for `
            + `are seat #0, seat #1 and seat #2 (your VAULTODY mobile app), or seat #0, seat #1 `
            + `and seat #3 (your own co-signer node). Download the ticket again from the `
            + `Dashboard, and if it is unchanged, contact VAULTODY.`
        );
    }

    /**
     * THE ONE PLACE THE RECIPIENT OF AN ENVELOPE IS DECIDED, and the security property the whole
     * ceremony rests on.
     *
     * VAULTODY's own seats are sealed to the key COMPILED INTO THIS BUILD. The ticket's copy of
     * that key is read, compared, and used for nothing else: it is a check, never a source. A
     * ticket that names a different key for a VAULTODY seat is not a ticket to retry with - it is
     * either a corrupted download or a substituted one, and in the second case going ahead hands
     * every part of the client's key to whoever substituted it.
     *
     *   | Whose key                          | Where it comes from                              |
     *   |------------------------------------|--------------------------------------------------|
     *   | The VAULTODY backend nodes (0, 1)  | pinned in the build; the ticket's copy is        |
     *   |                                    | compared, never trusted                          |
     *   | The client's self-hosted co-signer | the ticket - the client generated it when they   |
     *   | (seat 3)                           | stood their node up and can read it back from it |
     *   | The client's handset (seat 2)      | the ticket - generated on the device             |
     *
     * The split is not an oversight. Only OUR keys can be pinned: a client's co-signer key and a
     * handset key are created per client and per device, long after a build is cut, so for those
     * seats the party that generated the key is the party that vouches for it.
     *
     * @param {object} metadata
     * @param {number[]} seats
     * @param {string} algorithm
     * @return {Map<number, Buffer>} seat -> the canonical DER the part will be sealed to
     * @private
     */
    _recipients(metadata, seats, algorithm) {
        const recipients = new Map();
        const missingFromBuild = [];
        const mismatched = [];
        const unusable = [];

        for (const index of seats) {
            const onTheTicket = nodeKeys.canonicalPublicKey(metadata.players[index]);
            if (onTheTicket === null) {
                unusable.push(index);
                continue;
            }

            if (!nodeKeys.isPinnedSeat(index)) {
                recipients.set(index, onTheTicket);
                continue;
            }

            const pinned = this.pinnedNodePublicKeys.get(index);
            if (pinned === undefined) {
                missingFromBuild.push(index);
                continue;
            }

            if (!nodeKeys.samePublicKey(pinned, onTheTicket)) {
                mismatched.push({index: index, pinned: pinned, onTheTicket: onTheTicket});
                continue;
            }

            // The build's bytes, not the ticket's - even though the two just agreed. What is
            // sealed to must come from the pinned table, so that the comparison can never
            // degrade into "use the ticket if it looks close enough".
            recipients.set(index, pinned);
        }

        if (missingFromBuild.length) {
            throw new Error(
                `This copy of the VAULTODY Vault Recovery Tool was built without VAULTODY's own `
                + `node keys, so it cannot lock a part for ${this._seatNameList(missingFromBuild)} `
                + `and it will not guess at them. Nothing has been sealed and your files are `
                + `untouched. This is a fault in the tool itself, not in anything you chose: do `
                + `not retry, and get a signed release build of the tool from VAULTODY instead. `
                + `(Whoever cuts that build fills the production mpc node public keys into `
                + `src/lib/vaultodyNodePublicKeys.js first - it ships empty on purpose.)`
            );
        }

        if (mismatched.length) {
            const quoted = mismatched
                .map(seat => `${this._seatNameList([seat.index])} - this tool: `
                    + `${nodeKeys.fingerprint(seat.pinned)}, this ticket: `
                    + `${nodeKeys.fingerprint(seat.onTheTicket)}`)
                .join('\n');

            throw new Error(
                `This ticket does not match the keys this tool was built with. Its ${algorithm} `
                + `session names a different key for ${this._seatNameList(mismatched.map(seat => seat.index))} `
                + `than the one VAULTODY published and this tool carries, so your key parts would `
                + `be locked for someone who is not VAULTODY. Nothing has been sealed. Do not try `
                + `again and do not upload anything - contact VAULTODY, tell them the key import `
                + `ticket does not match the recovery tool, and read them this:\n${quoted}`
            );
        }

        if (unusable.length) {
            throw new Error(
                `The public key this ticket gives for ${this._seatNameList(unusable)} is not a key a `
                + `part can be locked to. Download the ticket again from the Dashboard, and if it `
                + `is still refused, contact VAULTODY - nothing has been sealed.`
            );
        }

        return recipients;
    }

    /**
     * The seats the ticket asks for, ascending, so the sealed file reads in seat order whatever
     * order the ticket's map came in.
     *
     * THE ROSTER IS THE ONE THING THE TICKET IS STILL THE AUTHORITY ON, and it has to be: which
     * seats a vault has is a per-vault, per-client fact that no build can know. Pinning replaces
     * the VALUE at VAULTODY's own seats (see _recipients), never the list of seats.
     *
     * A seat with no public key on the ticket is refused even where the tool holds a pinned one,
     * because the ticket's copy exists to be COMPARED: a ticket that cannot be compared is a
     * ticket that cannot be checked. For a client-held seat there is no second place to look at
     * all, and going ahead would leave that node with nothing to import.
     *
     * @param {object} metadata
     * @param {string} algorithm
     * @return {number[]}
     * @private
     */
    _seats(metadata, algorithm) {
        const players = metadata.players;
        if (players === null || typeof players !== 'object' || Object.keys(players).length === 0) {
            throw new Error(
                `The ${algorithm} session of the ticket names no players, so there is no node to `
                + `seal anything to. Download the ticket again from the Dashboard.`
            );
        }

        const seats = [];
        const withoutAPublicKey = [];
        for (const key of Object.keys(players)) {
            const index = Number(key);
            if (!Number.isInteger(index) || index < 0) {
                throw new Error(
                    `The ${algorithm} session of the ticket names a seat that is not a player `
                    + `number ("${key}"). Download the ticket again from the Dashboard.`
                );
            }

            if (typeof players[key] !== 'string' || players[key].length === 0) {
                withoutAPublicKey.push(index);
            }

            seats.push(index);
        }

        if (withoutAPublicKey.length) {
            throw new Error(
                `The ticket gives no public key for ${this._seatList(withoutAPublicKey)}, so that `
                + `part cannot be locked for its node. Download the ticket again from the `
                + `Dashboard, and if it is still incomplete, reset the import and start it over.`
            );
        }

        return seats.sort((left, right) => left - right);
    }

    /**
     * The key a migration brings in, as it was declared when the import was initialized and
     * echoed back on the ticket. It is required there - a node has no row to read it from - and
     * the chain code of it is what the node binds, so this is the value the tool must seal
     * against rather than one the client types a second time.
     *
     * @param {object} ticket
     * @param {string} algorithm
     * @param {RecoveryDataEntity} recoveryData
     * @return {{algorithm: string, chainCode: string, publicKey: string}}
     * @private
     */
    _findExternalKey(ticket, algorithm, recoveryData) {
        const declared = Array.isArray(ticket.externalKeys) ? ticket.externalKeys : [];
        const externalKey = declared.find(key => key.algorithm === algorithm);
        if (externalKey === undefined) {
            throw new Error(
                `This is a migration, but the ticket does not say which ${algorithm} key is being `
                + `brought in. Start the import again in the Dashboard and give the key's chain `
                + `code and public key there.`
            );
        }

        if (typeof externalKey.chainCode !== 'string' || !HEX.test(externalKey.chainCode)) {
            throw new Error(
                `The ${algorithm} key on the ticket has no usable chain code. Start the import `
                + `again in the Dashboard and check the chain code you give it.`
            );
        }

        const expectedLength = EXTERNAL_PUBLIC_KEY_HEX_LENGTH[algorithm];
        if (typeof externalKey.publicKey !== 'string'
            || !HEX.test(externalKey.publicKey)
            || externalKey.publicKey.length !== expectedLength
        ) {
            throw new Error(
                `The ${algorithm} key on the ticket is not a ${expectedLength}-character `
                + `compressed public key. Start the import again in the Dashboard and check the `
                + `public key you give it.`
            );
        }

        // The nodes rebuild the group public key from the parts they import and compare it with
        // the one they were handed. If the ticket describes a different key from the one this
        // package holds, the whole ceremony runs and then every node refuses - so it is refused
        // here instead, where the client can still pick the other file.
        //
        // The declared CHAIN CODE gets no such comparison, deliberately: nothing downstream
        // compares it either, it is simply the one the nodes will store, and on a migration the
        // client's declaration of it is the only statement of what it should be.
        const packagePublicKey = recoveryData.getCompressedPublicKey().toString('hex');
        if (externalKey.publicKey.toLowerCase() !== packagePublicKey.toLowerCase()) {
            throw new Error(
                `The ticket is for the ${algorithm} key ${externalKey.publicKey}, but the `
                + `${algorithm} backup data file holds the key ${packagePublicKey}. They are not `
                + `the same key - choose the backup file for the key you are migrating, or start `
                + `the import again with this key's public key.`
            );
        }

        return externalKey;
    }

    /**
     * Every seat the ticket names must import its own part: a node left out does not fail the
     * ceremony honestly, it takes part in it holding nothing, and the sharing that comes out is
     * not the key that went in. So a package that cannot cover the ticket is refused here,
     * before anything is sealed to anyone.
     *
     * The ticket lists every seat of the vault: 0 and 1 always, plus EITHER the client's handset
     * at 2 (mobile_cosigner) OR the client's own co-signer at 3 (server_cosigner). Seat 2 is
     * sealed here like any other - a mobile_cosigner backup package already carries that seat's
     * part, because the Dashboard appends it when the package is produced - even though seat 2's
     * envelope is later handed to the handset rather than driven by the signer. The check below
     * is indifferent to which seats those are, and keeps refusing a package that is short any
     * seat the ticket DOES list.
     *
     * @param {RecoveryDataEntity} recoveryData
     * @param {number[]} seats
     * @param {boolean} isRecovery
     * @param {number} oldThreshold
     * @param {string} algorithm
     * @private
     */
    _assertPackageCoversTheTicket(recoveryData, seats, isRecovery, oldThreshold, algorithm) {
        const missing = seats.filter(index => recoveryData.getKeyPart(index) === null);
        if (recoveryData.getKeyParts().every(part => part.getIndex() === null)) {
            throw new Error(
                `The ${algorithm} backup data file holds no part for any seat in the ticket. A `
                + `package whose parts carry no player index - the shared/ERS format - cannot be `
                + `used for a key import, because a part's seat cannot be identified from its `
                + `position. This tool seals from ${ACCEPTED_PACKAGE}.`
            );
        }

        if (missing.length) {
            throw new Error(
                `The ticket asks for ${seats.length} ${algorithm} parts and the ${algorithm} `
                + `backup data file holds no part for ${this._seatList(missing)}. Every seat in `
                + `the ticket has to import its own part, so check this is the backup of the `
                + `vault being imported - an older package, taken before the vault gained a `
                + `player, will be short like this.`
            );
        }

        if (isRecovery && seats.length < oldThreshold) {
            throw new Error(
                `The ${algorithm} ceremony needs ${oldThreshold} parts and the ticket asks for `
                + `only ${seats.length}. Reset the import in the Dashboard and start it again.`
            );
        }
    }

    /**
     * Opens one part, turning a key that cannot open the package into a sentence about the two
     * files rather than the RSA library's own wording.
     *
     * @param {RecoveryDataEntity} recoveryData
     * @param {number} index
     * @param {string} rsaPrivateKey
     * @param {string} algorithm
     * @return {Buffer}
     * @private
     */
    _openKeyPart(recoveryData, index, rsaPrivateKey, algorithm) {
        try {
            return recoveryData
                .getKeyPart(index)
                .recoverKeyShare(rsaPrivateKey, recoveryData.getCurve())
                .toArrayLike(Buffer, 'be', envelope.POINT_BYTES_LENGTH);
        } catch (e) {
            throw new Error(
                `The ${algorithm} part for seat #${index} could not be opened with this RSA `
                + `private key. The backup data file and the private key have to be the pair you `
                + `made together.`
            );
        }
    }

    /**
     * @param {number[]} seats
     * @return {string}
     * @private
     */
    _seatList(seats) {
        return seats.map(seat => `seat #${seat}`).join(', ');
    }

    /**
     * The same list, saying WHOSE node each seat is. A client asked to compare a key, or told
     * that a seat cannot be sealed to, cannot act on a bare player number.
     *
     * @param {number[]} seats
     * @return {string}
     * @private
     */
    _seatNameList(seats) {
        return seats.map(seat => `seat #${seat} (${nodeKeys.seatName(seat)})`).join(', ');
    }

    /**
     * @param {string[]} items
     * @return {string}
     * @private
     */
    _list(items) {
        return items.join(' and ');
    }
}

module.exports = KeyImportService;
