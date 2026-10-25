<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Contributing to LUME

LUME is an end-to-end encrypted messenger. The relay is blind: it stores and
forwards sealed envelopes and never sees plaintext, keys, or who sent what. All
cryptography runs on the client, in a C++ core shared by every app.

The specification is the authority: [`docs/CRYPTO.md`](docs/CRYPTO.md) and
[`docs/PROTOCOL.md`](docs/PROTOCOL.md). Code that disagrees with it is a bug in
one of the two — fix the one that is wrong, in the same change.

## Layout

```
core/      liblume, C++20 — crypto, identity, vault, handshake, ratchet, wire, session, C API
server/    lume-relay, C++20 — WebSocket over Boost.Beast/Asio, SQLite
android/   Kotlin + Jetpack Compose; the core through JNI over the C API
desktop/   WinUI 3 (C++/WinRT); the core linked directly
docs/      specification
legal/     privacy policy, terms and the other user-facing policies
brand/     name and logo — trademarks, not covered by the code licence
```

Dependencies come from vcpkg in manifest mode with a pinned baseline. A new
dependency needs a stated reason and is reviewed like code.

## Every file

**Starts with the licence header**, in the comment syntax of its language:

```cpp
// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only
```

```kotlin
// SPDX-FileCopyrightText: 2026 LUME Inc.
// SPDX-License-Identifier: AGPL-3.0-only
```

```cmake
# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only
```

```markdown
<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->
```

Files that cannot carry a header (images, binary fixtures) are covered in
[`REUSE.toml`](REUSE.toml). The repository is checked with
[`reuse lint`](https://reuse.software) in CI.

**Carries no comments besides that header.** Code says what it does through
names, types and small functions; the specification says why. A piece of code
that needs a paragraph to be understood needs to be rewritten or specified in
`docs/`. [`tools/check_comments.py`](tools/check_comments.py) enforces this in
CI.

## Cryptography

1. **Primitives come from libsodium and liboqs only.** Never implement a cipher,
   MAC, hash, KDF, signature or KEM. The composition is specified in
   `docs/CRYPTO.md` before it is written.
2. **Secrets live in `SecretBytes`** (sodium_malloc-backed, wiped on
   destruction) — never in `std::string`, `std::vector`, a log line, an
   exception message, or a JNI or WinRT object that outlives the call.
3. **Compare secrets in constant time** (`sodium_memcmp`), never with `==`.
4. **Fail closed.** A cryptographic error never leads to sending or showing
   unencrypted data, and never to a silent fallback to a weaker mode.
5. **Commit state only on success.** Ratchet and handshake state change only
   after an authenticated decrypt succeeds; every failure leaves the session
   exactly as it was.
6. **Bound everything an attacker controls**: skipped keys, message sizes,
   prekey counts, collection lengths.
7. **Domain-separate every derivation** with a distinct, versioned label from
   `docs/CRYPTO.md` §12.
8. Randomness comes from `randombytes_buf` — never `rand()`, `<random>` or the
   clock.

## Wire format

- One canonical, versioned binary codec in `core/wire`. The relay and every
  client use the same parser.
- Decoding rejects non-canonical input, trailing bytes, unknown versions and
  out-of-range lengths, and never reads past the buffer it was given.
- Every decoder has a fuzz target.

## Relay

1. Never log, inspect or store plaintext, keys, or the sender of an envelope.
2. Every frame is decoded through `core/wire` before anything acts on it.
3. Every operation is rate limited. Address keys collapse IPv6 to its /64;
   account keys come from the authenticated identity, never a claimed one.
4. Every table has a TTL, a row cap, or both. Prepared statements only.
5. Configuration is validated at boot; an invalid or missing value stops the
   process instead of falling back to a default.
6. Errors returned to a client carry a code, never internals.

## C++

- C++23, which needs GCC 13, Clang 19 or MSVC 19.40 at least — older ones
  lack `std::expected`. Warnings are errors: `-Wall -Wextra -Wpedantic -Wconversion
  -Wsign-conversion -Wshadow -Wold-style-cast -Werror` on GCC and Clang,
  `/W4 /WX /permissive-` on MSVC — see `cmake/LumeCompilerOptions.cmake`.
- RAII for every resource. No owning raw pointers, no `new` or `delete`.
- No undefined behaviour; sanitizer builds stay clean.
- Untrusted bytes are `std::span<const std::uint8_t>` with explicit lengths.
  They are never reinterpreted as anything other than bytes.
- Expected failures return `lume::crypto::Result<T>` (`std::expected`).
  Exceptions never cross the C ABI.
- `clang-tidy` 22 with [`.clang-tidy`](.clang-tidy) reports nothing; CI fails
  otherwise.

## Tests

- Every module ships with its tests in the same change: unit tests, published
  test vectors where they exist, property-based tests for codecs and protocol
  invariants, and a fuzz target for every parser.
- CI runs GCC and Clang with AddressSanitizer, UndefinedBehaviorSanitizer and,
  for the relay, ThreadSanitizer; MSVC on Windows; the Android build on an
  emulator. Line coverage of `core/` below 90 % fails the build.
- Property tests run 500 cases each (`LUME_PROPERTY_RUNS`); a failure prints
  the seed that reproduces it.
- Build and test locally with the presets: `cmake --preset windows-msvc`,
  `cmake --build --preset windows-msvc-debug`, `ctest --preset
  windows-msvc-debug`, and the `linux-*` equivalents. `VCPKG_ROOT` must point
  at a vcpkg checkout of the commit pinned in `vcpkg.json`.
- Never weaken or delete an assertion to make a run pass. When a test fails,
  decide first whether the code or the test is wrong, and say which.
- Report only what was observed. A check that could not run is reported as
  not run, with the reason — never as passed.

## Git

- `dev` is the working branch, `main` is stable. Work on `feat/…`, `fix/…` or
  `chore/…`, open a pull request into `dev`, and promote `dev` to `main` only
  with CI green. Nobody pushes to `main` directly.
- Conventional Commits, short and plain. A body only when it carries what the
  diff cannot.
- No force-push to `main` or `dev`.

## Security review

Changes to `core/`, authentication, the wire format, rate limiting, storage,
the C API, JNI, dependencies, CI and secret handling are not mergeable until
someone other than the author has reviewed the diff against the specification.
Nothing signs off on its own security.

Vulnerabilities are reported privately — see [`SECURITY.md`](SECURITY.md) — and
are not discussed in public issues until fixed.

## Contributor licence agreement

By opening a pull request you agree that:

1. your contribution is licensed under the GNU Affero General Public License
   v3.0 only, like the rest of the code;
2. you grant LUME Inc. a perpetual, worldwide, non-exclusive, royalty-free and
   irrevocable licence to use, reproduce, modify, sublicense and distribute
   your contribution, including under licence terms other than the AGPL; and
3. you have the right to make the contribution, and it is your own work or you
   are entitled to submit it under these terms.

Sign every commit off (`git commit -s`) to confirm this. Point 2 is what lets
LUME Inc. offer the code under a commercial licence alongside the AGPL; without
it the project could not accept outside contributions and keep that option.
