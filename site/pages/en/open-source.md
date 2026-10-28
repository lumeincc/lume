<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Open source

A messenger asks you to trust it with your conversations. LUME's answer is to
let anyone read the code, the specification and the policies, and check them
against each other.

## Where the code is

Everything is public at
[github.com/lumeincc/lume](https://github.com/lumeincc/lume): the
cryptographic core, the [specification](/spec/crypto/), the
[policies](/legal/) and this website. The relay, the Android app and the
Windows app will be developed in the same repository.

## The licence: GNU AGPL v3.0

The code is free software under the
[GNU Affero General Public License, version 3 only](/licence/). In short:

- You may use, study, change and share it.
- If you distribute it, changed or not, you pass on the same freedoms: the
  source code, under the same licence.
- If you run a changed version as a service that people use over a network, you
  must offer those people its source code.

This summary is not the licence; [the full text](/licence/) is what applies.

## The name and logo are not under the code licence

The LUME name and logo belong to LUME Inc. Someone who installs an app called
LUME, with the LUME logo, has to be able to rely on it being the build LUME Inc.
publishes, not a modified copy that might log messages. Forks are welcome; they
need their own name and icon. See [Name and logo](/trademarks/).

## What LUME is built on

| Component | What for | Licence |
|---|---|---|
| [libsodium](https://libsodium.org) | X25519, Ed25519, XChaCha20-Poly1305, SHA-2, HMAC, HKDF, Argon2id, randomness | ISC |
| [liboqs](https://openquantumsafe.org) | ML-KEM-768 | MIT |
| BIP39 English wordlist | the words of the recovery phrase | MIT |

The tests also use GoogleTest, RapidCheck and nlohmann/json, and test vectors
from Project Wycheproof (Apache 2.0) and Trezor (MIT). The licence of every
file is recorded in the repository in the [REUSE](https://reuse.software)
format.

## Check it yourself

- One command configures, builds and runs every test and writes a report:
  `pwsh tools/test.ps1` on Windows or `sh tools/test.sh` on Linux. What it
  needs is in [CONTRIBUTING.md](../../../CONTRIBUTING.md).
- `lume-lab`, built next to the tests, walks through accounts, recovery, the
  post-quantum handshake, attacks and safety numbers on the real core, and marks
  every check `[ ok ]` or `[FAIL]`.
- The specification says what the code must do. Code that disagrees with it is
  a bug in one of the two.

## Contributing

Contributions arrive as pull requests, signed off under the contributor licence
agreement in [CONTRIBUTING.md](../../../CONTRIBUTING.md). Security bugs are
reported privately — see [Security](/security/).

## This website

The website is built from the same repository: [`site/`](../../../site) holds a
small generator that uses only Python's standard library, and the policies are
rendered straight from [`legal/`](../../../legal), so the website and the
repository cannot disagree. It runs no scripts, sets no cookies and loads
nothing from other servers — see [Privacy on this website](/legal/website/).
