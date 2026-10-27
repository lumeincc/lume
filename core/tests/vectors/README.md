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
| `ratchet.json` | a 24-step Double Ratchet conversation with header encryption: keys skipped inside a chain and at a DH step, reordered and late messages, two replays that must be refused without changing anything, every header and body byte, CRYPTO.md §6; computed by an independent JavaScript implementation whose XChaCha20 is checked against Wycheproof first |

```bash
node core/tools/generate_identity_vectors.mjs core/third_party/bip39/english.txt core/tests/vectors/trezor/bip39_vectors.json core/tests/vectors/lume/identity.json
node core/tools/generate_safety_vectors.mjs core/tests/vectors/lume/identity.json core/tests/vectors/lume/safety.json
node core/tools/generate_handshake_vectors.mjs core/tests/vectors/lume/identity.json core/tests/vectors/wycheproof core/tests/vectors/lume/handshake.json
node core/tools/generate_ratchet_vectors.mjs core/tests/vectors/lume/handshake.json core/tests/vectors/wycheproof core/tests/vectors/lume/ratchet.json
```

The generator checks its own phrase encoding against the Trezor vectors before
it writes anything. CI regenerates every generated file and fails if it
differs from what is committed.
