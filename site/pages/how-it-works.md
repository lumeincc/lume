<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# How LUME protects you

LUME is an end-to-end encrypted messenger. This page explains how it works,
what it protects and what it does not. Each part links to the section of the
[specification](/spec/crypto/) that gives the details.

> [!NOTE]
> LUME is in development and there is no app yet. This page describes how LUME
> will work when it is released. [What is built so far](#what-exists-today) is
> listed at the end.

## An account without a phone number

When you create an account, your device draws 256 random bits and shows them to
you as 24 English words: your **recovery phrase**. Your identity keys, which
prove that you are you, are derived from those words on your device
([§3](/spec/crypto/#3-identity)).

- We never receive the phrase, so we cannot restore it. **If you lose both the
  phrase and your device, the account is gone for good.**
- Anyone who has the phrase can act as you. Write it down on paper and show it
  to no one.
- You choose a username so that people can find you, but your contacts know
  you by your keys. A username can later pass to someone else; your keys
  cannot.
- LUME never asks for a phone number, an e-mail address, your name or your
  address book.

## Messages are encrypted on your device

A message is encrypted on the sender's device and decrypted on the
recipient's. The server in between, the **relay**, only stores and forwards
sealed envelopes. It holds no one's private key and cannot open an envelope
([relay protocol](/spec/protocol/)).

## Protection against quantum computers

Someone could record encrypted traffic today and keep it until a quantum
computer can break the key exchange that protected it. So LUME starts every
conversation with two key exchanges together: **X25519**, the classical one
used across the internet today, and **ML-KEM-768**, the post-quantum one
standardised as FIPS 203. The shared key stays secret unless **both** are
broken ([§5.6](/spec/crypto/#56-why-hybrid)).

## Keys that keep changing

After the first message, LUME uses the **Double Ratchet**, the design known
from Signal, with encrypted message headers
([§6](/spec/crypto/#6-double-ratchet-with-header-encryption)). Every message
gets its own key, and a key is deleted once it has been used.

- **Forward secrecy.** Someone who takes your device later cannot decrypt
  messages they recorded earlier, because those keys no longer exist. There are
  time-limited exceptions, listed [below](#what-lume-does-not-protect).
- **Healing.** If someone steals a conversation's keys once and then loses
  access, one round trip of messages locks them out again. This healing relies
  on classical cryptography only.

## The server does not know who is writing

- **Sealed sender.** Each envelope is sealed to the recipient, so the relay
  sees whom it is for, never whom it is from
  ([§8](/spec/crypto/#8-sealed-sender)).
- **Delivery tokens.** Your app gives each contact a random token to write to
  you with. The relay checks the token but is not told who holds it. When you
  block someone, their token stops delivering, and the relay gives them no
  sign of it ([§9](/spec/crypto/#9-delivery-tokens-and-blocking)).
- **No groups on the server.** Group names, members and roles exist only on the
  members' devices ([§11.2](/spec/crypto/#112-groups)).
- **No IP addresses on disk.** The relay uses your address in memory to deliver
  messages and limit abuse, and never writes it down. The one exception: a
  message from a stranger without an invite is stored with a hash of the
  sender's network block (an IPv6 /48 or IPv4 /24), keyed with a key that
  changes every day. It holds no full address, and it is deleted with the
  message ([Privacy Policy](/legal/privacy/)).

## What stays on your device

Messages, contacts and keys are kept only on your device, in an encrypted
**vault**. It opens with your passphrase and, where the device supports it, a
key held in secure hardware ([§10](/spec/crypto/#10-vault--data-at-rest)). The
apps opt out of cloud backup, so nothing is copied to Google or Microsoft
either.

## What LUME does not protect

The specification lists what LUME does **not** protect against
([§1](/spec/crypto/#1-goals-and-non-goals)):

- **Your IP address and when you are online.** The relay sees the address of
  every connection. Someone who runs it, or watches it live, can match senders
  and recipients by address and timing. If that matters to you, use Tor or a
  VPN.
- **How much you receive and when.** The relay sees the volume and timing of
  envelopes for each recipient, and patterns such as one connection sending
  many envelopes of the same size at once, which can suggest a group message.
- **Whether a username exists.** A taken username looks taken, even when its
  owner has turned discoverability off.
- **Names, if you never compare safety numbers.** The relay vouches for which
  username belongs to which keys. Whoever controls the relay's signing key could
  attach a name to the wrong person. The safety number is the check that does
  not depend on the relay — see [Verify a contact](/safety-number/).
- **Some recordings, for a limited time.** The first messages of some new
  conversations rely on a key the recipient's device keeps for up to 40 days
  (longer if the app is not opened in that time), and keys for messages that
  arrive out of order are kept for up to 14 days. Someone who recorded those
  messages and takes the device within that time can read them.
- **A stolen recovery phrase.** Whoever copies the phrase, or the identity key,
  can act as you until you create a new account. LUME cannot yet replace an
  identity: recovering on a new device locks out the old device, not a thief who
  holds the phrase.
- **Who wrote to you, against someone who later takes your device.** A recorded
  envelope reveals its sender to someone who takes the recipient's device while
  the key it was sealed to still exists, which is up to 40 days, or while the
  token it arrived on is still linked to that contact.
- **That you blocked someone.** The relay tells them nothing, but they will see
  that your replies and delivery receipts stop.
- **That you recovered your account.** People who can look up your account's
  keys can tell that it was recovered on a new device, and nothing more.
- **Deleted messages on flash memory.** LUME overwrites what it deletes, but
  phone and SSD storage can keep old copies out of any app's reach. Someone with
  your device *and* your passphrase may recover them.
- **Healing against a quantum computer.** The handshake is post-quantum; the
  ratchet's healing steps are classical.
- **A well-funded mass attack.** Proof of work, limits and quotas make spam and
  flooding expensive, not impossible.
- **That a report is genuine.** A report shows what the reporter says they
  received. LUME cannot prove that the reported message was really sent.
- **A hostile program on Windows.** It can stop the vault from unlocking for a
  while by using up the TPM's allowance of failed attempts.
- **A compromised device.** Malware running as you reads what you read.

## Libraries and checks

- The cryptography comes from **libsodium** and **liboqs**. LUME combines
  vetted primitives and does not invent its own
  ([§2](/spec/crypto/#2-primitives)).
- The primitives are tested against published vectors, including those of
  Project Wycheproof, and LUME publishes its own vectors for each construction
  it builds ([§14](/spec/crypto/#14-test-vectors)).
- When it starts, the core tests itself. If the test fails, the core encrypts
  and decrypts nothing at all.
- A cryptographic error never leads to sending or showing anything unencrypted.
- The code is public. If you find a flaw, [report it](/security/).
- **There has been no independent security audit yet.**

## What exists today

Nothing is released yet. The core library is built and tested for:

- the primitives and their start-up self-test;
- accounts from a recovery phrase, and safety numbers;
- the wire format;
- the hybrid post-quantum handshake and the Double Ratchet;
- the encoding of message content, sealed sender and padding;
- directory key lists, username certificates and introduction cards;
- the formats of the vault: its keys, header, records and manifest.

The vault cannot yet store anything on a device, use secure hardware or be
unlocked. Delivery tokens, receipts, attachments, group messaging, the session
layer, the relay and the apps are not built yet. The specification is a draft,
revision {{spec-revision}}, and can still change.

## Read the specification

For the exact details, read the specification itself.

- [Cryptography](/spec/crypto/) — every key, derivation and construction.
- [Relay protocol](/spec/protocol/) — what the server does, stores and limits.
