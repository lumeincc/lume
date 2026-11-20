<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME

[Website](https://lumeincc.github.io/lume/) ·
[How it works](https://lumeincc.github.io/lume/how-it-works/) ·
[Documentation](https://lumeincc.github.io/lume/docs/)

LUME is an end-to-end encrypted messenger, in development for Android and
Windows. All cryptography runs on the device, in a C++ core that every app will
share. The relay server is designed to store and forward sealed envelopes
without access to message content, keys or the sender's identity.

The cryptography and the relay protocol are specified in [`docs/`](docs/). The
specifications are drafts and change as the code is written. Read them before
you treat any part of the design as built or as a security guarantee.

## Status

Nothing is released, and there is no app to install yet.

Built and tested in the core library:

- the cryptographic primitives and their start-up self-test;
- accounts from a 24-word recovery phrase, with identity and device keys;
- safety numbers and invite fingerprints;
- the wire format;
- the PQXDH handshake, which combines X25519 and ML-KEM-768;
- the Double Ratchet with header encryption;
- the encoding of message content, sealed sender and padding;
- directory key lists, username certificates and introduction cards;
- the vault's formats: its key schedule, header, records, sealed record
  addresses and sealed manifest.

Not built yet:

- the vault's storage, its use of hardware key stores, and unlocking;
- the session layer, which will hold sessions, prekeys, receipts and delivery
  tokens, and the C API;
- attachments and group messaging;
- the relay server;
- the Android and Windows apps.

## Repository

| Path | Contents |
| --- | --- |
| [`core/`](core/) | The core library, C++23: cryptography, identity, handshake, ratchet, content encoding, sealed sender, wire format and vault formats |
| [`docs/`](docs/) | Cryptography and relay protocol specifications |
| [`legal/`](legal/) | Privacy policy, terms and the other user-facing policies |
| [`site/`](site/) | The website and its generator |
| [`tools/`](tools/) | Test scripts, CI helpers and `lume-lab`, a walkthrough of the core |
| [`brand/`](brand/) | The LUME name and logo, not covered by the code licence |

## Build and test

The project uses CMake and vcpkg in manifest mode. Check out vcpkg at the
baseline pinned in [`vcpkg.json`](vcpkg.json) and set `VCPKG_ROOT` to its path.

To configure, build and run every test:

**Linux**
```sh
sh tools/test.sh
```

**Windows**
```powershell
pwsh tools/test.ps1
```

Each script runs the CMake workflow for its platform and writes an HTML test
report to `build/<preset>/test-report.html`.
[`CONTRIBUTING.md`](CONTRIBUTING.md) lists the toolchain requirements and the
project's rules.

To build the website locally, with Python 3.11 or later:

```sh
python site/build.py
```

## Security and design

- [`docs/CRYPTO.md`](docs/CRYPTO.md): the cryptographic design
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): the relay protocol
- [`SECURITY.md`](SECURITY.md): how to report a vulnerability privately
- [`CONTRIBUTING.md`](CONTRIBUTING.md): contribution and review rules

The specifications state the intended properties and the known limits. LUME
has not been independently audited. Read the goals and non-goals in section 1
of the cryptography specification.

## Contributing

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md). Changes to security-sensitive
parts are reviewed against the specifications. By opening a pull request, you
agree to the licence terms set out there.

## Licence

The code and documentation are licensed under the
[GNU Affero General Public License v3.0 only](LICENSE). The LUME name and logo
are **not** covered by that licence; see [`TRADEMARKS.md`](TRADEMARKS.md).
