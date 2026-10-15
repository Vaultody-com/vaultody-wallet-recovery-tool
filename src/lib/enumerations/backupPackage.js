'use strict';

// The ecies-p256-v1 backup package: what the embedded wallet (WaaS) e-mails an
// end user, opened offline with their 24 recovery words. Every value here is a
// wire constant shared with the wallet host and with Vaultody's nodes
// (vaultody-mpc-core, pkg/backup); changing one breaks every package already
// written.

const VERSION = 'ecies-p256-v1';

// Separates the words-to-scalar derivation from every other use of the entropy.
const KEY_INFO = 'vaultody:backup:v1';

const WORD_COUNT = 24;
const ENTROPY_BYTES = 32;

// A share's plaintext is its 32-byte polynomial point, big-endian; the chain code is its 32 bytes.
const SHARE_BYTES = 32;

const NONCE_BYTES = 12;
const TAG_BYTES = 16;

// 3-of-3: indices 0 and 1 are Vaultody's nodes, 2 is the browser player. Every
// one of them is needed to rebuild a key.
const SHARE_INDICES = [0, 1, 2];

// Every key has its own chain code, sealed as one more part next to that key's
// shares under the key's own id, so a chain code moved to another key does not
// open there (core c414b629).
const CHAIN_CODE_INDEX = 0;
const CHAIN_CODE_ALGORITHM = 'chain-code';
const chainCodeLabel = (keyId) => ({keyId: keyId, index: CHAIN_CODE_INDEX, algorithm: CHAIN_CODE_ALGORITHM});

// Packages written before that change carry one chain code for the whole
// package under this key-agnostic label. Still opened, applied to every key.
const LEGACY_CHAIN_CODE_LABEL = {keyId: 'master-chain-code', index: 0, algorithm: '-'};

// The browser player's transport identity, sealed next to the shares so the
// widget can carry on with the wallet. It moves no funds; the tool skips it.
const IDENTITY_KEY_ID = 'mpc-identity';

// Q and E on the wire: uncompressed P-256, lowercase hex.
const RECIPIENT_PATTERN = /^04[0-9a-f]{128}$/;

module.exports = {
    VERSION: VERSION,
    KEY_INFO: KEY_INFO,
    WORD_COUNT: WORD_COUNT,
    ENTROPY_BYTES: ENTROPY_BYTES,
    SHARE_BYTES: SHARE_BYTES,
    NONCE_BYTES: NONCE_BYTES,
    TAG_BYTES: TAG_BYTES,
    SHARE_INDICES: SHARE_INDICES,
    CHAIN_CODE_INDEX: CHAIN_CODE_INDEX,
    CHAIN_CODE_ALGORITHM: CHAIN_CODE_ALGORITHM,
    chainCodeLabel: chainCodeLabel,
    LEGACY_CHAIN_CODE_LABEL: LEGACY_CHAIN_CODE_LABEL,
    IDENTITY_KEY_ID: IDENTITY_KEY_ID,
    RECIPIENT_PATTERN: RECIPIENT_PATTERN,
};
