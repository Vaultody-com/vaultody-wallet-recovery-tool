'use strict';

const BN = require('bn.js');
const {test, expect} = require('@playwright/test');

const KeyImportService = require('../src/lib/services/keyImportService');
const RecoveryDataEntity = require('../src/lib/entities/recoveryDataEntity');
const Validator = require('../src/validation/validator');
const envelope = require('../src/lib/utils/keyImportEnvelope');
const curveUtils = require('../src/lib/utils/curve');
const lagrange = require('../src/lib/utils/lagrange');
const privateKeyTypeEnum = require('../src/lib/enumerations/privateKeyType');
const {CURVE, DOMAIN_PARAMS} = require('../src/lib/enumerations/curve');
const {
    SEATS,
    OLD_THRESHOLD,
    NEW_THRESHOLD,
    KEY_ID,
    OLD_KEY_ID,
    clientRsaKey,
    toPaddedHex,
    buildBackupPackage,
    buildNodeKeys,
    buildTicket,
} = require('./keyImportFixture');

const domainParams = DOMAIN_PARAMS[CURVE.SECP256K1];

/**
 * @param {object} ticket
 * @param {object} backup
 * @return {object}
 */
function seal(ticket, backup) {
    return new KeyImportService().sealKeyParts(
        ticket,
        new RecoveryDataEntity(backup.data),
        Buffer.from(clientRsaKey.privateKey),
        privateKeyTypeEnum.RAW_PEM
    );
}

test('every seat in the ticket gets an envelope only its own node can open', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);

    expect(result.sealedSeats).toEqual(SEATS);
    expect(result.seatsWithoutAPart).toEqual([]);
    expect(result.algorithm).toBe(envelope.ALGORITHM.ECDSA);
    expect(result.keyId).toBe(KEY_ID);

    const binding = {
        kind: envelope.KIND.RECOVERY,
        keyId: KEY_ID,
        oldKeyId: OLD_KEY_ID,
        algorithm: envelope.ALGORITHM.ECDSA,
        newThreshold: NEW_THRESHOLD,
        oldThreshold: OLD_THRESHOLD,
        publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
        chainCode: backup.chainCode,
    };

    for (const part of result.sealedParts) {
        // The node rebuilds the binding from its OWN index, so the envelope only opens under
        // the index it was addressed to.
        const point = envelope.openEnvelope({
            senderPublicKey: part.senderPublicKey,
            payload: part.payload,
            recipientPrivateKey: nodeKeys.get(part.index).privateKey,
            sessionId: metadata.sessionId,
            binding: {...binding, importerIndex: part.index},
        });

        expect(point.toString('hex')).toBe(toPaddedHex(backup.shares.get(part.index)));
    }
});

test('an envelope addressed to one seat does not open at another', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);
    const [first] = result.sealedParts;

    expect(() => envelope.openEnvelope({
        senderPublicKey: first.senderPublicKey,
        payload: first.payload,
        recipientPrivateKey: nodeKeys.get(SEATS[1]).privateKey,
        sessionId: metadata.sessionId,
        binding: {
            kind: envelope.KIND.RECOVERY,
            keyId: KEY_ID,
            oldKeyId: OLD_KEY_ID,
            algorithm: envelope.ALGORITHM.ECDSA,
            importerIndex: SEATS[1],
            newThreshold: NEW_THRESHOLD,
            oldThreshold: OLD_THRESHOLD,
            publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
            chainCode: backup.chainCode,
        },
    })).toThrow();
});

test('the sealed points still interpolate to the key the package was made from', () => {
    const backup = buildBackupPackage();
    const nodeKeys = buildNodeKeys();
    const ticket = buildTicket(nodeKeys);
    const metadata = ticket.keyImportMetadata[0];

    const result = seal(ticket, backup);

    const indices = [];
    const values = [];
    for (const part of result.sealedParts) {
        const point = envelope.openEnvelope({
            senderPublicKey: part.senderPublicKey,
            payload: part.payload,
            recipientPrivateKey: nodeKeys.get(part.index).privateKey,
            sessionId: metadata.sessionId,
            binding: {
                kind: envelope.KIND.RECOVERY,
                keyId: KEY_ID,
                oldKeyId: OLD_KEY_ID,
                algorithm: envelope.ALGORITHM.ECDSA,
                importerIndex: part.index,
                newThreshold: NEW_THRESHOLD,
                oldThreshold: OLD_THRESHOLD,
                publicKey: new RecoveryDataEntity(backup.data).getCompressedPublicKey(),
                chainCode: backup.chainCode,
            },
        });

        // The abscissa is the seat plus one, the same convention recoverPrivateKey uses.
        indices.push(new BN(part.index + 1));
        values.push(new BN(point));
    }

    const reconstructed = lagrange.reconstruct(indices, values, domainParams.n);

    expect(reconstructed.toString('hex')).toBe(backup.secret.toString('hex'));
    // And the sealing itself never had to form it: the retired group public key is read off the
    // package, not derived from a reassembled secret.
    expect(new RecoveryDataEntity(backup.data).getCompressedPublicKey().toString('hex'))
        .toBe(curveUtils.encodePoint(CURVE.SECP256K1, domainParams.g.mul(backup.secret)).toString('hex'));
});

test('a package whose parts are not polynomial points is refused, not silently sealed', () => {
    const backup = buildBackupPackage({sharing_type: 'multiplicative'});
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket, backup)).toThrow(/shamir/);
});

test('a ticket for the other algorithm is refused', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys(), {algorithm: envelope.ALGORITHM.EDDSA});

    expect(() => seal(ticket, backup)).toThrow(/no ecdsa session/);
});

test('a ticket with no session id is refused rather than sealed to nothing', () => {
    const backup = buildBackupPackage();
    const ticket = buildTicket(buildNodeKeys(), {sessionId: ''});

    expect(() => seal(ticket, backup)).toThrow(/sessionId/);
});

test('a package that cannot cover the retired threshold is refused', () => {
    const backup = buildBackupPackage();
    backup.data.key_parts = backup.data.key_parts.slice(0, 1);
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket, backup)).toThrow(/needs 2 parts/);
});

test('a shared/ERS package, whose parts name no seat, is refused', () => {
    const backup = buildBackupPackage();
    backup.data.key_parts = backup.data.key_parts.map(part => ({...part, index: null}));
    const ticket = buildTicket(buildNodeKeys());

    expect(() => seal(ticket, backup)).toThrow(/no part for any seat/);
});

test('the ticket constraints accept a well-formed ticket and refuse a broken one', () => {
    const validator = new Validator();
    const ticket = buildTicket(buildNodeKeys());

    expect(validator.validateKeyImportTicket(ticket)).toBeUndefined();
    expect(validator.validateKeyImportTicket({...ticket, kind: 'whatever'})).toBeDefined();
    expect(validator.validateKeyImportTicket({...ticket, keyImportMetadata: []})).toBeDefined();
});
