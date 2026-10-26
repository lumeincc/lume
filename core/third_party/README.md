<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Third-party data

## bip39/english.txt

The BIP39 English wordlist from
[bitcoin/bips](https://github.com/bitcoin/bips/blob/100ba872c808946155b1eeb8c4568058f2eea0a7/bip-0039/english.txt),
commit `100ba872c808946155b1eeb8c4568058f2eea0a7`, copied unchanged. SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. MIT —
[`LICENSES/MIT.txt`](../../LICENSES/MIT.txt).

`core/src/identity/wordlist.hpp` is generated from it; the generator refuses a
file with another hash, another word count, unsorted or non-lowercase words,
or words that share their first four letters:

```bash
node core/tools/generate_wordlist.mjs core/third_party/bip39/english.txt core/src/identity/wordlist.hpp
```
