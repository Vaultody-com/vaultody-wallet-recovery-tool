'use strict';

const fs = require('fs');
const path = require('path');
const {test, expect} = require('@playwright/test');

const RecoveryDataEntity = require('../src/lib/entities/recoveryDataEntity');
const {EXAMPLE_DATA_DIR} = require('./helpers');

// The chain code examples/data/recovery_data_ecdsa.json recovers to — it is the second half of
// the xPriv tests/recover.spec.js asserts through the UI.
const EXPECTED_ECDSA_CHAIN_CODE = '00aa73544eb7a9e8b5fbeb2304187d341a8c2edebd8b7b2dafd3ef8f60f29778';

const RSA_PRIVATE_KEY = fs.readFileSync(path.join(EXAMPLE_DATA_DIR, 'private_key.txt')).toString();

/**
 * @param {string} fileName
 * @return {object}
 */
function readRecoveryData(fileName) {
    return JSON.parse(fs.readFileSync(path.join(EXAMPLE_DATA_DIR, fileName)).toString());
}

/**
 * Flips one bit of the base64-encoded master chain code, leaving its length — and therefore the
 * tag/ciphertext split — untouched.
 *
 * @param {object} data
 * @param {number} byteOffset
 * @return {object}
 */
function corruptMasterChainCode(data, byteOffset) {
    const masterChainCode = Buffer.from(data['master_chain_code'], 'base64');
    masterChainCode[byteOffset] ^= 0x01;

    return {...data, master_chain_code: masterChainCode.toString('base64')};
}

test('the untouched example still recovers the same chain code', () => {
    const recoveryData = new RecoveryDataEntity(readRecoveryData('recovery_data_ecdsa.json'));

    expect(recoveryData.recoverChainCode(RSA_PRIVATE_KEY)).toBe(EXPECTED_ECDSA_CHAIN_CODE);
});

test('a corrupted master chain code throws instead of returning garbage', () => {
    // Before decipher.final() was called the GCM tag was set but never verified, so this
    // returned a plausible-looking but wrong chain code and the tool handed back a silently
    // wrong xPriv.
    const recoveryData = new RecoveryDataEntity(
        corruptMasterChainCode(readRecoveryData('recovery_data_ecdsa.json'), 0)
    );

    expect(() => recoveryData.recoverChainCode(RSA_PRIVATE_KEY))
        .toThrow('Master chain code failed authentication');
});

test('a corrupted authentication tag throws too', () => {
    const data = readRecoveryData('recovery_data_ecdsa.json');
    const tagOffset = Buffer.from(data['master_chain_code'], 'base64').length - 1;
    const recoveryData = new RecoveryDataEntity(corruptMasterChainCode(data, tagOffset));

    expect(() => recoveryData.recoverChainCode(RSA_PRIVATE_KEY))
        .toThrow('Master chain code failed authentication');
});

test('every byte of the ciphertext is covered by the tag', () => {
    const data = readRecoveryData('recovery_data_ecdsa.json');
    const length = Buffer.from(data['master_chain_code'], 'base64').length;

    for (let offset = 0; offset < length; offset++) {
        const recoveryData = new RecoveryDataEntity(corruptMasterChainCode(data, offset));

        expect(() => recoveryData.recoverChainCode(RSA_PRIVATE_KEY), `byte ${offset} unprotected`)
            .toThrow('Master chain code failed authentication');
    }
});

// A real secp256k1 backup carries public_key as the base64 of the SPKI header immediately followed
// by the base64 of the compressed point, joined with no separator. Because the header's base64 ends
// in '=' padding, the joined value has a '=' in the middle, and a single Buffer.from(...,'base64')
// truncates it to the header. The entity must decode both halves. This fixture is the exact shape a
// live QA server-cosigner backup produced, whose compressed key is the 03-prefixed point below.
test('reads a secp256k1 public_key that is two concatenated base64 segments', () => {
    const header = 'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgA=';               // ends in '=' padding
    const pointB64 = 'A0mObzbVgRsUMeWQyCd7BY9p0xLFShj+6N9WvJwQTCOP'; // 33-byte compressed point
    const entity = new RecoveryDataEntity({
        public_key: header + pointB64,
        sharing_type: 'shamir',
        version: '1',
        master_chain_code: 'AA==',
        master_chain_code_key: 'AA==',
        key_parts: [{data: 'AA==', index: 0}],
    });

    expect(entity.getCompressedPublicKey().toString('hex'))
        .toBe('03498e6f36d5811b1431e590c8277b058f69d312c54a18fee8df56bc9c104c238f');
});
