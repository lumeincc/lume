# Security

LUME is an encrypted messenger, so a security report is the most useful thing
you can send us. This page says how to send one, what we will do with it, and —
the part most projects leave out — what LUME does **not** protect you from
today.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting** on this repository: *Security →
Report a vulnerability*. It opens a private thread visible only to the
maintainer, which is what you want for anything that is not already public.

Please do not open a public issue for a security bug, and please do not disclose
it publicly before it is fixed.

Useful reports contain: what breaks, how to reproduce it, and what an attacker
gets out of it. A proof of concept is welcome and never required — a clear
description of the flaw is worth more than a working exploit.

### What to expect

LUME is written by one person. Being honest about that is more useful than
quoting a service-level agreement nobody is on call to meet:

- **First reply within 72 hours.** If you do not hear back, the message did not
  arrive — say so publicly without details and we will find it.
- **There is no bug bounty.** There is no money in this project. Credit in the
  release notes and in this file, if you want it; nothing else is on offer.
- **Fixes land in `dev` first**, behind the full test gate, then in `main`. You
  will get the commit.

## In scope

Anything that breaks a claim LUME makes:

- the cryptography — X3DH, the Double Ratchet, key derivation, the key vault,
  prekey handling, safety numbers;
- **the relay learning something it should not** — plaintext, keys, or metadata
  beyond what is documented below;
- request signing and the authentication middleware, WebSocket authentication;
- authorisation: reading or writing another account's messages, files, profile
  or groups;
- input validation, injection, rate-limit bypass;
- anything in the client that leaks key material out of the vault — into
  application state, storage, logs, or the DOM.

## Out of scope

Not because they do not matter, but because they are already known, already
written down, or not something a report can change:

- **The limitations listed in the next section.** They are deliberate and
  documented. A report describing one of them is not a finding; a report showing
  one is *worse than described* very much is.
- Denial of service from a single host against the free-tier deployment. The
  relay runs on a free plan with the resources that implies. What matters is
  whether the *protocol* enables amplification — that is in scope.
- Missing hardening headers with no demonstrated impact, and results copied out
  of an automated scanner without a working attack behind them.
- Social engineering, physical access to an unlocked device, and compromised
  operating systems. LUME assumes the device is not already owned by someone
  else.

## What LUME does not protect you from

Every messenger has a list like this. Most do not publish it.

**The relay sees who you write to when they are offline.** Message bodies are
sealed and the relay cannot read them. But an undelivered message is stored with
its sender and its recipient in the clear, and those join to usernames — so
whoever holds the database file can reconstruct a contact graph, with timestamps,
for the retention window (30 days). Delivered messages are deleted. This is
tracked and being worked on; until it is fixed, treat *who you talk to* as
visible to the relay operator, even though *what you say* is not.

**The relay knows who is in a group.** Group membership is stored in plaintext.
Group message content is not.

**Your unlock secret is the ceiling on everything at rest.** Local storage is
encrypted with a key derived from your passphrase using PBKDF2-SHA256 at 600,000
iterations. That is a strong function over a possibly weak input: the minimum is
eight characters, and eight digits is a secret an attacker with your device can
still search. Use a passphrase, not a PIN-shaped number.

**A web app asks you to trust the server that serves it.** Every page load
fetches JavaScript. A compromised or coerced host could serve modified code to
one user, and the cryptography would then be whatever that code says it is. This
is inherent to web delivery and not specific to LUME — it is the reason the
native clients exist. Reading the source here does not prove the bytes in your
browser match it.

**Undelivered messages can be lost.** The relay's storage is wiped on every
deployment by the hosting plan it runs on. A message accepted by the relay but
not yet collected does not survive that, and today the sender is not told.

**Anonymity is not the same as untraceability.** LUME asks for no phone number,
no email and no name. It does not hide your IP address from the relay, and it is
not a replacement for Tor or a VPN if a network observer is in your threat model.

## Cryptography

Reported in detail in [`docs/PROTOCOL.md`](docs/PROTOCOL.md). In one paragraph:
identity is an Ed25519 signing pair and an X25519 exchange pair, both derived
deterministically from a BIP39 phrase. First contact runs X3DH against the
recipient's prekey bundle, with the signed prekey's signature verified before any
Diffie-Hellman step. Messages use a Double Ratchet — a fresh key per message,
new ephemerals on each ratchet step — sealed with XSalsa20-Poly1305. Private keys
never leave the device and never enter application state.

**LUME does not invent cryptography.** It uses well-analysed constructions
through TweetNaCl. If you find that it has invented some by accident, that is
exactly the report we want.
