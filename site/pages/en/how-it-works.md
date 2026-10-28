<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# How LUME protects you

LUME is an end-to-end encrypted messenger. This page describes how it works,
what it protects and what it does not. Each part links to the section of the
[specification](/spec/crypto/) that describes it precisely.

> [!NOTE]
> LUME is in development and no app has been released. This page describes how
> LUME is designed to work; [what exists today](#what-exists-today) is listed at
> the end.

## Your account is a key, not a phone number

When you create an account, your device draws 256 random bits and shows them to
you as 24 English words: your **recovery phrase**. Your identity keys — what
makes you *you* on LUME — are calculated from those words, on your device
([§3](/spec/crypto/#3-identity)).

- We never receive the phrase, so we cannot restore it. **If you lose both the
  phrase and your device, the account is gone for good.**
- Anyone who has the phrase can act as you. Write it down, keep it offline and
  show it to no one.
- You choose a username so that people can find you. Your contacts recognise you
  by your keys, not by the name: a name can be released and registered again
  by someone else, a key cannot.
- LUME never asks for a phone number, an e-mail address, your name or your
  address book.

## Messages are locked on your device

A message is encrypted on the sender's device and decrypted on the recipient's.
The server in between — the **relay** — stores and forwards sealed envelopes it
cannot open. It never holds anyone's private key and never decrypts an envelope
([relay protocol](/spec/protocol/)).

## Ready for quantum computers

Someone could record encrypted traffic today and keep it until a quantum
computer can break the key exchange that protected it. So LUME starts every
conversation with two key exchanges at once: **X25519**, the classical one used
across the internet today, and **ML-KEM-768**, the post-quantum one
standardised as FIPS 203. The key that comes out stays secret as long as
**either** of them holds ([§5.6](/spec/crypto/#56-why-hybrid)).

## Keys that keep changing

After the first message, LUME uses the **Double Ratchet**, the design known from
Signal, with encrypted message headers
([§6](/spec/crypto/#6-double-ratchet-with-header-encryption)). Every message
gets its own key, and a key is deleted once it has been used.

- **Forward secrecy.** Someone who takes your device later cannot decrypt
  messages they recorded earlier, because those keys no longer exist. There are
  time-limited exceptions, listed [below](#what-lume-does-not-protect).
- **Healing.** If someone steals a conversation's keys once and then loses
  access, they are locked out again after one round trip of messages. This
  healing relies on classical cryptography only.

## The server does not know who is writing

- **Sealed sender.** Each envelope is sealed to the recipient, so the relay
  sees whom it is for, never whom it is from
  ([§8](/spec/crypto/#8-sealed-sender)).
- **Delivery tokens.** Your app gives each contact a random token to write to
  you with. The relay checks the token without learning who holds it. When you
  block someone, their token stops delivering, and the relay gives them no
  signal ([§9](/spec/crypto/#9-delivery-tokens-and-blocking)).
- **No groups on the server.** Group names, members and roles exist only on the
  members' devices ([§11.2](/spec/crypto/#112-groups)).
- **No IP addresses on disk.** The relay uses your address in memory to deliver
  messages and limit abuse, and never writes it down. The one exception: a
  message from a stranger without an invite carries a hash of their network,
  keyed with a key that changes every day; the address cannot be recovered from
  it, and it is deleted with the message ([Privacy Policy](/legal/privacy/)).

## What stays on your device

Messages, contacts and keys are kept only on your device, in an encrypted
**vault** locked with your passphrase and, where the device supports it, a
hardware-protected key ([§10](/spec/crypto/#10-vault--data-at-rest)). The apps
opt out of cloud backups, so nothing is copied to Google or Microsoft either.

## What LUME does not protect

The specification lists separately what LUME does **not** protect against
([§1](/spec/crypto/#1-goals-and-non-goals)). Here is that list:

- **Your IP address and when you are online.** The relay sees the address of
  every connection. Someone who runs it, or watches it live, can match senders
  and recipients by address and timing. If that matters to you, use Tor or a
  VPN.
- **How much you receive and when.** The relay sees the volume and timing of
  envelopes for each recipient, and patterns such as one connection sending many
  envelopes of the same size at once, which can suggest a group message.
- **Whether a username exists.** A taken username looks taken, even when its
  owner has turned discoverability off.
- **Names, if you never compare safety numbers.** The relay vouches for which
  username belongs to which keys. Whoever controls the relay's signing key could
  attach a name to the wrong person. The safety number is the check that does
  not depend on the relay — see [Verify a contact](/safety-number/).
- **Some recordings, for a limited time.** The first messages of some new
  conversations rely on a key the recipient's device keeps for up to 40 days
  (longer if the app is not opened), and keys of messages that arrive out of
  order are kept for up to 14 days. Someone who recorded those messages and
  takes the device within that time can read them.
- **A stolen recovery phrase.** Whoever copies the phrase, or the identity key,
  can act as you until you create a new account. This version cannot replace an
  identity: recovering on a new device locks out the old device, not a thief who
  holds the phrase.
- **Who wrote to you, against someone who later takes your device.** A recorded
  envelope reveals its sender to someone who takes the recipient's device while
  the key it was sealed to still exists — up to 40 days — or while the token it
  arrived on is still linked to that contact.
- **That you blocked someone.** The relay tells them nothing, but they will see
  that your replies and delivery receipts stop.
- **That you recovered your account.** People who can look up your account's
  keys can tell that it was recovered on a new device, and nothing more.
- **Deleted messages on flash memory.** LUME overwrites what it deletes, but
  phone and SSD storage can keep old copies beyond any app's reach. Someone with
  your device *and* your passphrase may recover them.
- **Healing against a quantum computer.** The handshake is post-quantum; the
  ratchet's healing steps are classical.
- **A well-funded mass attack.** Proof of work, limits and quotas make spam and
  flooding expensive, not impossible.
- **That a report is genuine.** A report shows what the reporter says they
  received; LUME cannot prove that the reported message was really sent.
- **A hostile program on Windows** can lock the vault for a while by using up
  the TPM's allowance of failed attempts.
- **A compromised device.** Malware running as you reads what you read.

## Libraries and checks

- The cryptography comes from **libsodium** and **liboqs**. LUME combines
  vetted primitives and does not invent its own
  ([§2](/spec/crypto/#2-primitives)).
- Every primitive is tested against published vectors, including Google's
  Project Wycheproof, and LUME publishes its own vectors for every construction
  ([§14](/spec/crypto/#14-test-vectors)).
- When it starts, the core runs a self-test. If the test fails, nothing is
  encrypted or decrypted at all, rather than something working insecurely.
- A cryptographic error never leads to sending or showing anything unencrypted.
- The code is public. If you find a flaw, [report it](/security/).
- There has been **no independent security audit yet**.

## What exists today

The cryptographic core is built and tested: the primitives and their self-test,
accounts from a recovery phrase, safety numbers, the hybrid post-quantum
handshake, the Double Ratchet and the wire format. Message content, sealed
sender, the vault, the relay and the apps are not built yet, and no app has been
released. The specification is a draft, revision {{spec-revision}}, and can
still change.

## Read the specification

For precision, read the specification itself. It is in English.

- [Cryptography](/spec/crypto/) — every key, derivation and construction.
- [Relay protocol](/spec/protocol/) — what the server does, stores and limits.
