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
