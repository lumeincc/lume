<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME

[Website](https://lumeincc.github.io/lume/) ·
[How it works](https://lumeincc.github.io/lume/how-it-works/) ·
[Documentation](https://lumeincc.github.io/lume/docs/)

</div>

---

LUME is an end-to-end encrypted messenger for desktop and Android, built around a shared C++ core. The relay is designed to store and forward sealed envelopes without access to message plaintext, keys or sender identity.

The cryptography and relay protocol are specified in [`docs/`](docs/). Those specifications are drafts and evolve alongside the implementation; read them before treating any design detail as a shipped feature or security guarantee.

## Project status

LUME is under active development. There is no public release to install yet. This repository is for the source code, specifications and development work.

## Project map

| Path | Contents |
| --- | --- |
| [`core/`](core/) | Shared C++23 core: cryptography, identity, vault, sessions and wire format |
| [`server/`](server/) | C++23 relay |
| [`android/`](android/) | Android client, Kotlin and Jetpack Compose |
| [`desktop/`](desktop/) | Windows desktop client, WinUI 3 and C++/WinRT |
| [`docs/`](docs/) | Cryptography and relay protocol specifications |
| [`site/`](site/) | Website and generated documentation |
| [`legal/`](legal/) | User-facing policies |

## Build and test

The project uses CMake and vcpkg in manifest mode. Use a vcpkg checkout matching the baseline pinned in [`vcpkg.json`](vcpkg.json), and set `VCPKG_ROOT` to its path.

Run the full configure, build and test workflow:

**Linux**
```sh
sh tools/test.sh
```

**Windows**
```powershell
pwsh tools/test.ps1
```

The test scripts run the corresponding CMake workflow and produce an HTML test report under `build/`. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for toolchain requirements, project conventions and details.

To build the static website locally with Python 3.11:

```sh
python site/build.py
```

## Security and design

- [`docs/CRYPTO.md`](docs/CRYPTO.md) — cryptographic design and its current status
- [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — relay protocol
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability privately
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution and review process

The specifications describe intended properties and known limitations; they are not a claim that the project has been independently audited. Please read the threat model and non-goals in the cryptography specification.

## Contributing

Start with [`CONTRIBUTING.md`](CONTRIBUTING.md). Changes to security-sensitive components require review against the specifications. By submitting a pull request, contributors agree to the licence terms described there.

## Licence

The code is licensed under the [GNU Affero General Public License v3.0 only](LICENSE). The LUME name and artwork are **not** covered by the code licence; see [`TRADEMARKS.md`](TRADEMARKS.md).
