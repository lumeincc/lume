<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Security

LUME is an encrypted messenger, so a vulnerability report is the most useful
thing you can send us.
Русская версия: [SECURITY.ru.md](SECURITY.ru.md).
Қазақша нұсқа: [SECURITY.kk.md](SECURITY.kk.md).

## Reporting a vulnerability

Use GitHub private vulnerability reporting in this repository: *Security →
Report a vulnerability*. Please do not open a public issue about a
vulnerability or disclose it before it is fixed.

A useful report says what breaks, how to reproduce it and what an attacker
gains. A proof of concept is welcome but not required.

First response within 72 hours. We tell you whether the vulnerability is
confirmed and when a fix is expected, and agree a publication date with you —
as a rule no later than 90 days after the report. There is no bug bounty.

## Good-faith research

If you look for vulnerabilities in good faith and by these rules, LUME Inc.
will not bring legal action or file complaints with law enforcement against you
over that research, and will treat it as authorised. The rules:

- test only your own accounts and those of participants who agreed;
- do not read, keep or change other people's data; if you reach it by
  accident, stop, delete it and tell us;
- do not degrade the service: no denial of service, spam or social engineering
  against users or staff;
- do not disclose the vulnerability to others before the fix or the agreed
  date.

This promise cannot override what the law requires and does not cover actions
that harm users.

## What is in scope now

**LUME is under development and nothing is deployed.** Reports about the code
in `core/`, `server/`, `android/`, `desktop/` and `site/` are welcome from the
first commit — above all anything that breaks a claim in
[`docs/CRYPTO.md`](docs/CRYPTO.md) or [`docs/PROTOCOL.md`](docs/PROTOCOL.md):
key agreement, the Double Ratchet, storage, the message format, or the relay
learning something it should not.

## What LUME holds to

- Cryptography comes from libsodium and liboqs. LUME composes vetted
  primitives and invents none. If it has invented one by accident, that is
  exactly the report we want.
- Fail closed: a cryptographic error never leads to sending or showing
  unencrypted data.
- The relay stores the minimum delivery needs: whom a sealed envelope is for,
  never who sent it.
- What LUME does not protect against is written down in the specification,
  not left for readers to discover.
