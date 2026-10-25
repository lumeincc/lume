<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Security

LUME is an encrypted messenger, so a security report is the most useful thing
you can send.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository: *Security →
Report a vulnerability*. Please do not open a public issue for a security bug,
and do not disclose it before it is fixed.

A useful report says what breaks, how to reproduce it, and what an attacker
gains. A proof of concept is welcome and never required.

Expect a first reply within 72 hours. There is no bug bounty.

## What is in scope right now

**LUME is under construction and nothing is deployed.** Reports against the
C++ code in `core/`, `server/`, `android/` and `desktop/` are in scope from
the first commit — above all anything that breaks a claim made in
[`docs/CRYPTO.md`](docs/CRYPTO.md) or [`docs/PROTOCOL.md`](docs/PROTOCOL.md):
key agreement, the ratchet, the vault, the wire format, or the relay learning
something it should not.

## Principles LUME is held to

- Cryptography comes from libsodium and liboqs. LUME composes vetted primitives
  and does not invent its own. If it has invented one by accident, that is
  exactly the report we want.
- Fail closed: a cryptographic error never results in sending or showing
  unencrypted data.
- The relay keeps the minimum it needs to deliver: who a sealed envelope is
  for, never who sent it.
- What LUME does not protect against is written down in the specification, not
  left for a reader to discover.
