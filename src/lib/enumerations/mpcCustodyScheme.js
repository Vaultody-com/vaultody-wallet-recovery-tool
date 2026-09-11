'use strict';

const {SEAT} = require('../vaultodyNodePublicKeys');

/**
 * The custody schemes a vault can run under, named exactly as vaults-manager names them, and the
 * seats each one puts in an import session.
 *
 * A key-import ticket does NOT carry the scheme - it carries the roster - so the tool reads the
 * scheme off the roster. That is sound because the roster is what the scheme decides: the seats
 * are built in exactly one place upstream (blockchain-signer's `_importNodeSet`, which both the
 * ticket-minting call and the ceremony-driving call read), so a roster and a scheme cannot drift
 * apart.
 *
 * WHAT v1 COVERS, AND WHY THE OTHER TWO ARE REFUSED RATHER THAN LEFT TO FAIL UPSTREAM:
 *
 *   mobile_cosigner  IN SCOPE. 3-of-3: the two VAULTODY nodes plus the client's handset.
 *   server_cosigner  IN SCOPE. 3-of-3: the two VAULTODY nodes plus the client's own co-signer.
 *   full_custody     OUT. VAULTODY holds every seat; there is no client-held seat to import
 *                    into, and the epic excludes it.
 *   hybrid           OUT. Both a handset and a self-hosted co-signer. It would otherwise fall
 *                    out of the roster code for free, so the refusal has to be explicit.
 *
 * The refusal is here, before anything is opened, because a client who seals a ticket the
 * Dashboard will refuse has spent an offline ceremony on nothing and learns why an hour later
 * from an error that names a vault field, not a file they can fix.
 */
const MPC_CUSTODY_SCHEME = Object.freeze({
    FULL_CUSTODY: 'full_custody',
    MOBILE_COSIGNER: 'mobile_cosigner',
    SERVER_COSIGNER: 'server_cosigner',
    HYBRID: 'hybrid',
});

/**
 * Seat roster -> scheme. Ascending seat order, which is the order `_seats` returns.
 */
const SCHEME_BY_ROSTER = Object.freeze({
    [[SEAT.VAULTODY_NODE_0, SEAT.VAULTODY_NODE_1].join(',')]: MPC_CUSTODY_SCHEME.FULL_CUSTODY,
    [[SEAT.VAULTODY_NODE_0, SEAT.VAULTODY_NODE_1, SEAT.MOBILE_DEVICE].join(',')]:
        MPC_CUSTODY_SCHEME.MOBILE_COSIGNER,
    [[SEAT.VAULTODY_NODE_0, SEAT.VAULTODY_NODE_1, SEAT.SERVER_COSIGNER].join(',')]:
        MPC_CUSTODY_SCHEME.SERVER_COSIGNER,
    [[SEAT.VAULTODY_NODE_0, SEAT.VAULTODY_NODE_1, SEAT.MOBILE_DEVICE, SEAT.SERVER_COSIGNER].join(',')]:
        MPC_CUSTODY_SCHEME.HYBRID,
});

const IMPORTABLE_SCHEMES = Object.freeze([
    MPC_CUSTODY_SCHEME.MOBILE_COSIGNER,
    MPC_CUSTODY_SCHEME.SERVER_COSIGNER,
]);

/**
 * Which scheme a roster of seats belongs to, or null when it is not a roster VAULTODY issues.
 *
 * @param {number[]} seats ascending
 * @return {string|null}
 */
function schemeOfRoster(seats) {
    return SCHEME_BY_ROSTER[seats.join(',')] || null;
}

module.exports = {
    IMPORTABLE_SCHEMES,
    MPC_CUSTODY_SCHEME,
    schemeOfRoster,
};
