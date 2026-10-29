<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Test vectors

## wycheproof/

From [Project Wycheproof](https://github.com/C2SP/wycheproof), directory
`testvectors_v1`, commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, copied
unchanged. Apache License 2.0 —
[`LICENSES/Apache-2.0.txt`](../../../LICENSES/Apache-2.0.txt).

| File | Checks |
|---|---|
| `x25519_test.json` | X25519, including low-order and non-canonical points |
| `ed25519_test.json` | Ed25519 verification, including malleable and non-canonical signatures |
| `hmac_sha256_test.json` | HMAC-SHA256, full and truncated tags |
| `hkdf_sha256_test.json` | HKDF-SHA256, including the output-length bound |
| `xchacha20_poly1305_test.json` | XChaCha20-Poly1305, including wrong nonce sizes and forged tags |
| `mlkem_768_keygen_seed_test.json` | ML-KEM-768 key generation from a seed |
| `mlkem_768_encaps_test.json` | ML-KEM-768 encapsulation, including keys that fail the modulus check |
| `mlkem_768_test.json` | ML-KEM-768 decapsulation, including malformed inputs |

To update, replace the files with those from a newer commit, change the commit
above, and run the full suite on every platform.

`core/src/crypto/known_answers.hpp`, the start-up self-test's vectors, is
generated from these files and must be regenerated when they change:

```bash
node core/tools/generate_known_answers.mjs core/tests/vectors/wycheproof core/src/crypto/known_answers.hpp
```

## trezor/

`bip39_vectors.json` from
[trezor/python-mnemonic](https://github.com/trezor/python-mnemonic/blob/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json),
commit `b57a5ad77a981e743f4167ab2f7927a55c1e82a8`, copied unchanged. MIT —
[`LICENSES/MIT.txt`](../../../LICENSES/MIT.txt). Only the English entropy and
mnemonic columns are used: the 24-word phrases must encode and decode exactly,
and the 12- and 18-word ones must be refused. The seeds in the file come from
BIP39's PBKDF2 step, which LUME does not run.

## lume/

LUME's own vectors, computed by an implementation independent of the core —
Node.js `crypto`, which is OpenSSL — so that both sides have to agree.

| File | Checks |
|---|---|
| `identity.json` | recovery phrase, identity keys, binding and device certificates, CRYPTO.md §3 |
| `safety.json` | fingerprints, safety numbers and invite fingerprints of the identities above, CRYPTO.md §12 |
| `handshake.json` | prekey signatures and both sides of the PQXDH handshake, with and without a one-time key, CRYPTO.md §4 and §5; the ML-KEM-768 values are the Wycheproof `mlkem_768_test.json` case each entry names, not copied; each case also gives `1/EK_A mod p`, which OpenSSL confirms gives the same X25519 results as `EK_A` and which must give other session keys |
| `ratchet.json` | a 24-step Double Ratchet conversation with header encryption: keys skipped inside a chain and at a DH step, reordered and late messages, two replays that must be refused without changing anything, every header and body byte, CRYPTO.md §6; computed by an independent JavaScript implementation whose XChaCha20-Poly1305, `core/tools/xchacha20poly1305.mjs`, is checked first against every Wycheproof case with a 192-bit nonce |
| `directory.json` | a directory key list signed by a root key and a username certificate for case 3 of `identity.json`, PROTOCOL.md §2.1 and CRYPTO.md §5.3: the exact signed messages, the Ed25519 signatures and the encodings, all from OpenSSL |
| `card.json` | an introduction card, CRYPTO.md §11.2: Bob's card for Alice with Bob's keys from `handshake.json` case 0 (the ML-KEM key from the Wycheproof case it names), a certificate signed by directory key 1 of `directory.json`, the exact card message, signature and encoding, and the card sealed under `card/key` and `card/ad` to a 20-day-old seal key of Alice, inside the 30 days a card seal allows; the generator checks every prekey signature, opens the sealed card, and confirms it does not open as a sealed message |
| `seal.json` | sealed sender to the seal key of `handshake.json` case 0, whose signature the generator verifies, CRYPTO.md §7.3 and §8: a first message with its initial header, a later one, and a 4095-byte inner that fills the 4096 bucket; and eleven envelopes that must be refused, each naming the one check that refuses it — the key id, the canonical check (twice: bit 255 set, and p + 9), the low-order check, the AEAD, the padding (four ways, one of them an empty plaintext), decoding, and the sender hint. Each refusal is sealed so that it authenticates as far as its check allows, and the generator confirms that skipping that check would change the outcome |
| `vault.json` | the vault, CRYPTO.md §10: Argon2id with one lane and a 32-byte output at the floor cost, at the Android default with a passphrase outside ASCII, and at the smallest cost libsodium accepts; the key schedule of §10.1, including the TPM binding with a real P-256 ECDH; a Keystore header and a TPM header that open under their master key, and six headers that must be refused; four records with their root terms, four records that must not open, roots that wrap around 2^256 and an incremental update, and a manifest with its tag and two refusals. Argon2id comes from `core/tools/argon2id.mjs`, an implementation of its own that the generator first checks against RFC 9106 §5.3; its three cases were also compared with the OpenSSL 3.5 command line when they were made |

```bash
node core/tools/generate_identity_vectors.mjs core/third_party/bip39/english.txt core/tests/vectors/trezor/bip39_vectors.json core/tests/vectors/lume/identity.json
node core/tools/generate_safety_vectors.mjs core/tests/vectors/lume/identity.json core/tests/vectors/lume/safety.json
node core/tools/generate_handshake_vectors.mjs core/tests/vectors/lume/identity.json core/tests/vectors/wycheproof core/tests/vectors/lume/handshake.json
node core/tools/generate_ratchet_vectors.mjs core/tests/vectors/lume/handshake.json core/tests/vectors/wycheproof core/tests/vectors/lume/ratchet.json
node core/tools/generate_seal_vectors.mjs core/tests/vectors/lume/identity.json core/tests/vectors/lume/handshake.json core/tests/vectors/lume/ratchet.json core/tests/vectors/wycheproof core/tests/vectors/lume/seal.json
node core/tools/generate_directory_vectors.mjs core/tests/vectors/lume/identity.json core/tests/vectors/lume/directory.json
node core/tools/generate_card_vectors.mjs core/tests/vectors/lume/identity.json core/tests/vectors/lume/handshake.json core/tests/vectors/lume/directory.json core/tests/vectors/wycheproof core/tests/vectors/lume/card.json
node core/tools/generate_vault_vectors.mjs core/tests/vectors/wycheproof core/tests/vectors/lume/vault.json
```

The generator checks its own phrase encoding against the Trezor vectors before
it writes anything. CI regenerates every generated file and fails if it
differs from what is committed.
