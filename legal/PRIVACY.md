<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME Privacy Policy

**Status: draft.** Takes effect on the day the first public build of LUME is
released; that date will replace this line.
Русская версия: [PRIVACY.ru.md](PRIVACY.ru.md).

## 1. Who we are

LUME is operated by **LUME Inc.** (ТОО «LUME Inc.»), a limited liability
partnership registered in the Republic of Kazakhstan, BIN 260740032421,
Temirtau, Karaganda Region. LUME Inc. is the owner and operator of the
databases described below and the controller of the personal data in them.

> [!IMPORTANT]
> **To be filled in before release:** the address for privacy requests (see
> the [contact page](CONTACT.md)).

Until then, use private vulnerability reporting on
[github.com/lumeincc/lume](https://github.com/lumeincc/lume).

## 2. The short version

LUME is built so that we hold as little about you as delivery requires.

- We **cannot read your messages, calls, attachments or contact list.** They
  are end-to-end encrypted on your device; we never have the keys.
- We **do not ask for** a phone number, an email address, your name, your
  address book or your location.
- We **do not store who sends a message.** For a message waiting to be
  delivered, our server knows who it is for, never who it is from.
- We have **no advertising, no analytics, no trackers** and no third-party
  SDKs in the apps.
- We **do not sell** data, and there is nothing to sell.

## 3. What our server holds

| Data | Why | How long |
|---|---|---|
| **Username** you choose | so contacts can find you; it is public unless you turn discoverability off | until you delete your account, or after 365 days without the app connecting |
| **Public keys** (identity key and prekeys) | so others can start an encrypted conversation with you; public keys cannot decrypt anything on their own | as above; one-time prekeys are deleted when used |
| **Discoverability setting** | whether your username can be looked up | as above |
| **Day the account was created, day it last connected** — a date, never a time | to delete abandoned accounts after 365 days | as above |
| **Delivery tokens** — random values your app issues to each contact, stored only as hashes | to accept messages from your contacts and refuse everyone you block, without the server knowing who those contacts are | until you revoke them or delete your account |
| **Invite codes**, stored only as hashes | to let someone reach you when you are not discoverable | 24 hours |
| **Messages waiting for delivery** — encrypted, unreadable to us, marked only with the recipient | to hand them to you when you next connect | deleted as soon as your app confirms receipt, and in any case after 30 days |
| **Attachments** — encrypted, unreadable to us | to let the recipient download them | 30 days |
| **Reports** another user makes about messages from you — the reported messages and your identity keys, sealed so that only LUME Inc. can open them | to act on abuse ([Terms of Use](TERMS.md), section 4) | 90 days, or longer where the law requires a report to be preserved |
| **A released username**, stored only as a hash | so that a deleted or expired name cannot be registered again at once | 31 days |

## 4. What passes through but is not kept

- **Your IP address and connection times.** The server needs them to talk to
  your device and uses them, in memory, to limit abuse (for example how many
  accounts one address can create per hour). They are **not written to disk or
  to logs.** The hosting provider that runs our server may see them on its own
  network; see section 7.
- **Typing indicators, read receipts and presence** are encrypted messages like
  any other and are dropped if you are offline.
- **Operational logs** record events, counts, durations and error codes. They
  contain no usernames, account identifiers, addresses or message data.

## 5. What stays on your device

Your messages, contacts, contact names, profile picture, keys and settings are
stored **only on your device**, encrypted with a key derived from your
passphrase and, where the device supports it, a hardware-protected secret. We
have no copy. The apps disable operating-system cloud backups of this data, so
it is not uploaded to Google or Microsoft either.

Your **recovery phrase** is shown once, on your device. We never receive it and
cannot recover it for you.

## 6. Legal basis

- **Performing the service you asked for** (GDPR art. 6(1)(b)): account data,
  keys, tokens and messages waiting for delivery.
- **Legitimate interest in keeping the service safe** (GDPR art. 6(1)(f)): the
  in-memory use of IP addresses for rate limiting.
- **Your consent**, given when you create an account, as required by the Law of
  the Republic of Kazakhstan "On Personal Data and Their Protection". You can
  withdraw it at any time by deleting your account.

## 7. Who else is involved

- **Hosting provider.** Our server runs on infrastructure we rent; the
  provider is not chosen yet — see the note below.
- **App stores.** Google Play, RuStore and Microsoft Store process your
  download under their own privacy policies. LUME does not receive data from
  them about you.
- **No one else.** We do not use advertising networks, analytics services,
  crash-reporting services or push-notification services that receive your
  data.

> [!IMPORTANT]
> **To be filled in before release:** the hosting provider, the country where
> the server is located and any resulting cross-border transfer. The Law of the
> Republic of Kazakhstan "On Personal Data and Their Protection" requires
> personal data to be stored in a database located in Kazakhstan; where the
> server runs, and what that means for users outside Kazakhstan, needs a
> lawyer's review.

We disclose data to authorities only as described in our
[Law Enforcement Policy](LAW-ENFORCEMENT.md), and only what section 3 lists —
we have nothing else.

## 8. Your rights

You can, at any time and from inside the app:

- **see** what the server holds about your account;
- **turn discoverability off**, so no one can look your username up;
- **revoke** any contact's delivery token, which stops their messages reaching
  you;
- **delete your account**, which removes everything in section 3 that belongs
  to it at once, except reports other users made and a hash of the username,
  which is held for 31 days and then freed — see
  [Deleting your account](ACCOUNT-DELETION.md).

Because we know nothing about you except your account's keys, requests are
made from the app, signed by your device — that is how we know a request is
yours. You also have the right to complain to the authority that supervises
personal-data protection in your country; in Kazakhstan, the authorised body
for personal data protection.

## 9. Age

LUME is not intended for anyone under 16. If the law where you live sets a
higher age for using a messaging service without a parent's consent, that age
applies.

## 10. Security

Messages are protected by end-to-end encryption with a hybrid post-quantum key
exchange, described in full in [docs/CRYPTO.md](../docs/CRYPTO.md). The source
code is public. If we ever learn that data we hold was accessed without
authorisation, we will say so in the app and on our website, and notify the
authorities as the law requires.

## 11. Changes

We will announce changes to this policy in the app before they take effect. The
history of this document is public in our repository.
