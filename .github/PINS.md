<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Pinned third-party artefacts

Everything CI downloads is pinned by commit or by hash. Workflows cannot carry
comments, so this table says what each pin is. Update a pin and its row in the
same change, and check the new value against the upstream source as shown.

| Artefact | Pin | Version | Check |
|---|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 | `gh api repos/actions/checkout/git/ref/tags/v7.0.1` |
| `actions/cache` | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` | v6.1.0 | `gh api repos/actions/cache/git/ref/tags/v6.1.0` |
| vcpkg | `817892b0ecbc6af994dd6df999c73faf795adbf2` | baseline in `vcpkg.json` | the commit in `microsoft/vcpkg` |
| liboqs source | SHA512 `d4a48335…be151` in `vcpkg/ports/liboqs/portfile.cmake` | 0.15.0 | `sha512sum` of `github.com/open-quantum-safe/liboqs/archive/0.15.0.tar.gz` |
| gitleaks | SHA-256 `551f6fc8…f2470eb` | 8.30.1, `linux_x64` | the asset digest on the GitHub release |
| apt.llvm.org signing key | fingerprint `6084F3CF814B57C1CF12EFD515CF4D18AF4F7421` | Clang and clang-tidy 22 | `tools/ci/install-llvm.sh` refuses a key file holding any other key and trusts only this one |
| Clang and clang-tidy 22 packages | **not pinned** | newest `llvm-toolchain-noble-22` build | apt.llvm.org keeps only its newest build, so a version pin would break; the packages are verified against the pinned key |
| Runner image tools: Node.js, Python, CMake, gpg, Visual Studio | **not pinned** | as shipped in `ubuntu-24.04` and `windows-2025` | GitHub's image release notes |
| gcovr and its dependencies | hashes in `tools/ci/coverage-requirements.txt` | gcovr 8.7 | regenerate with `uv pip compile --generate-hashes --python-platform x86_64-manylinux_2_39 --python-version 3.12` |
| reuse and its dependencies | hashes in `tools/ci/reuse-requirements.txt` | reuse 6.2.0 | as above |
| Project Wycheproof vectors | commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` | `testvectors_v1` | see `core/tests/vectors/README.md` |
