<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME Privacy Policy

**Status: draft.** Takes effect on the day the first public LUME build is
released; this line will then be replaced by that date.
Русская версия: [PRIVACY.ru.md](PRIVACY.ru.md).
Қазақша нұсқа: [PRIVACY.kk.md](PRIVACY.kk.md).

This policy is the document setting out LUME Inc.'s policy on the collection,
processing and protection of personal data within the meaning of article 25(2)
sub-paragraph 1-1) of the Law of the Republic of Kazakhstan "On Personal Data
and Their Protection". It also contains the information owed to data subjects
under articles 13 and 14 of the EU General Data Protection Regulation (GDPR).
The consent you give when you create an account is set out in
[Consent to the Collection and Processing of Personal Data](CONSENT.md).

## 1. Who we are

The owner and operator of the digital asset in which LUME users' personal data
is processed (the LUME relay server) is **LUME Inc.** (ТОО «LUME Inc.»), a
limited liability partnership registered in the Republic of Kazakhstan, BIN
260740032421, Temirtau, Karaganda Region. In GDPR terms, LUME Inc. is the
controller.

LUME Inc. appoints a person responsible for organising the processing of
personal data. Reach that person at the personal-data address on the
[contact page](CONTACT.md).

> [!IMPORTANT]
> **To be filled in before release:** the address for personal-data requests
> and the representative in the European Union (GDPR article 27) — see the
> [contact page](CONTACT.md).

Until then, use private reports at
[github.com/lumeincc/lume](https://github.com/lumeincc/lume).

## 2. In short

LUME is built so that we hold exactly as much about you as delivering messages
needs.

- We **cannot read** your messages, attachments or contact list. They are
  end-to-end encrypted on your device; we hold no keys that decrypt them.
- We **do not ask** for your phone number, e-mail, name, address book or
  location.
- We **do not store who sent a message.** For a message awaiting delivery, the
  server knows whom it is addressed to and not whom it is from.
- The apps contain **no ads, analytics, trackers** or third-party SDKs.
- We **do not sell or share** data for advertising or profiling.

## 3. What the server stores, why and for how long

This is the complete list; the server holds no other personal data about you.
It is the list of personal data necessary and sufficient for LUME within the
meaning of article 25(2) sub-paragraph 1) of the Kazakh law "On Personal Data
and Their Protection".

| Data | Why | How long |
|---|---|---|
| **Your username**, which you choose | so contacts can find and verify you; visible to other LUME users unless you turn off search by name | until you delete the account, or 365 days without the app connecting |
| **Your account's public keys**: identity key, device key, and the signed and one-time keys others use to start a conversation (prekeys) | so others can start an encrypted conversation with you and the server can check that requests come from you; public keys decrypt nothing | the same; a one-time key is deleted when it is handed out, a signed key when a new one replaces it |
| **The account's generation number** — how many times the account was recovered on a new device | to disconnect the old device after a recovery | the same |
| **The discoverability setting** | whether you can be found by name | the same |
| **The day the account was created and the day it last connected** — the date only, no time | to delete abandoned accounts after 365 days and to limit new accounts | the same |
| **Records that one-time keys were handed out**: which key, on which day, nothing about who asked for it | so the app can top up its stock of keys and not keep spare ones | 15 days |
| **Delivery tokens** — random values your app issues to each contact; only their hashes are stored, with the day each was created and last used | to accept messages from your contacts and refuse blocked ones without knowing who your contacts are | until you revoke them or delete the account; a token left over from a previous device and not used — 45 days |
| **Invite codes**, hashes only | so people can reach you while search by name is off | 24 hours |
| **Messages awaiting delivery** — encrypted, unreadable to us, labelled only with the recipient; for a message from a stranger without an invite, also a hash of the network it was sent from (see section 4) | to hand them to you when you next connect and to keep you from being flooded with spam | deleted as soon as you acknowledge them, and after 30 days in any case |
| **Attachments** — encrypted, unreadable to us | so the recipient can download them | up to 30 days or until the download count runs out |
| **Reports** by other users about your messages — the messages and the sender's identity keys, sealed so that only LUME Inc. can open them | to act on abuse ([Terms of Use](TERMS.md), section 6) | 90 days, or longer where the law requires the report to be kept |
| **Held and barred usernames**, hashes only | so a freed name cannot be taken again at once, and a name barred for abuse cannot be taken again | a freed name — 31 days; a barred name — while the bar lasts |

The certificate that vouches for your username is signed on request and not
stored.

## 4. What passes through the server but is not stored

- **IP address and connection time.** The server needs them to reach your
  device and uses them in memory against abuse — for example, to limit how
  many accounts one network can create per hour. **They are never written to
  disk or to logs.** The rate-limit counters live in a fixed-size table and are
  evicted.
- **A hash of the sender's network, for messages from strangers.** When a
  stranger writes to you without an invite, a hash of their network (the /48
  IPv6 or /24 IPv4 block), keyed with a key that changes every day, is kept
  with the message. It stops one network from filling your queue. The address
  cannot be recovered from it, and it is deleted with the message.
- **Typing indicators, read receipts and online status** are encrypted messages
  like any other; if you are offline they are dropped.
- **Service logs** hold events, counts, durations and error codes — no
  usernames, account identifiers, tokens, addresses or message content.

**What no server can technically hide.** While a connection is open, the
server sees its address. Someone watching the server live could correlate
incoming and outgoing connections by address and timing. We do not record any
of this; if it matters to you, use Tor or a VPN. Details are in section 1 of
the [cryptography specification](../docs/CRYPTO.md).

## 5. What stays on your device

Messages, contacts, contact names, profile photos, keys and settings are stored
**only on your device**, encrypted under a key derived from your passphrase
and, where the device supports it, a hardware-protected secret. We have no
copy. The apps opt out of the operating system's cloud backup for this data, so
it does not reach Google or Microsoft either.

Your **recovery phrase** is shown once, on your device. We never receive it and
cannot recover it.

## 6. Grounds for processing

**Under the law of the Republic of Kazakhstan**, the ground is your consent to
the collection and processing of personal data, which you give in the app when
you create an account. Its text is in
[Consent to the Collection and Processing of Personal Data](CONSENT.md).
Without consent, data is processed only in the cases listed in article 9 of the
Kazakh law "On Personal Data and Their Protection".

**Under the GDPR**, where it applies to you:

- **performance of the contract** — the [Terms of Use](TERMS.md)
  (article 6(1)(b)): account data, keys, tokens, invites and messages awaiting
  delivery;
- **legitimate interest** in protecting the service and its users from abuse
  (article 6(1)(f)): IP addresses in memory, the sender's network hash, held
  and barred usernames, reports;
- **legal obligation** (article 6(1)(c)): keeping reports and answering lawful
  requests where the law requires it.

You may object to processing based on legitimate interest (GDPR article 21);
deleting the account ends it entirely.

We make no decisions about you based solely on automated processing that have
legal effects for you. The only automated measures are rate limits and the
proof-of-work check at registration; they temporarily slow down or refuse
requests from a network and do not assess you as a person.

## 7. Who else is involved

- **The hosting provider.** The server runs on rented infrastructure in a data
  centre. The provider processes data only on our instructions and under
  contract and cannot see its content: messages and attachments are encrypted,
  and everything else is listed in section 3.
- **App stores.** The store you installed LUME from handles downloads and
  updates under its own rules, as an independent controller. LUME receives no
  data about you from app stores.
- **Public authorities** — only in the cases and to the extent described in the
  [Law Enforcement Policy](LAW-ENFORCEMENT.md), and only what is listed in
  section 3: we have nothing else.
- **No one else.** We use no ad networks, analytics, crash reporting or push
  services that would receive your data, and we do not share data for
  marketing.

> [!IMPORTANT]
> **To be filled in before release:** the hosting provider and the server's
> country. Article 12(2) of the Kazakh law "On Personal Data and Their
> Protection" requires personal data to be stored in a database or digital
> asset located in the Republic of Kazakhstan. While the server is in
> Kazakhstan there is no cross-border transfer: the data of users in any
> country is collected directly by their apps and stored in Kazakhstan.

## 8. How we protect data

- **End-to-end encryption** with a hybrid post-quantum key exchange: messages
  and attachments on the server are encrypted under keys we do not have. The
  design is in [docs/CRYPTO.md](../docs/CRYPTO.md); the source code is open.
- **Minimisation:** the server holds only what section 3 lists, for limited
  periods; tokens, invites and freed names are stored as hashes; dates are kept
  to the day.
- **Deletion without remnants:** the server's database is configured to
  overwrite deleted records instead of leaving them in the file.
- **Access:** only authorised staff of LUME Inc. can access the server; the
  key that signs usernames is held apart from it.

**If a breach happens.** If we discover a breach of personal-data security, we
will:

- notify the authorised body of the Republic of Kazakhstan for personal-data
  protection within the time the law sets — no later than one working day
  after discovery;
- notify the EU supervisory authority within 72 hours where the breach affects
  people the GDPR applies to and creates a risk for them;
- tell you in the app and on the website what happened, which data is affected
  and what to do, where the breach may affect your rights.

## 9. Your rights

You have the right to:

- **know** whether we hold personal data about you and get information about
  it and about the purposes, means and periods of processing — free of
  charge;
- **have it changed or completed** if it is inaccurate;
- **have data blocked, erased or destroyed** if it was collected or processed
  unlawfully, and to restrict processing;
- **receive your data** in a machine-readable form (portability);
- **object** to processing based on legitimate interest and to automated
  processing;
- **withdraw consent** — deleting the account withdraws it and ends processing
  at once, although the law allows up to 15 working days;
- **seek protection** from the authorised body for personal-data protection of
  the Republic of Kazakhstan or a court, and, where the GDPR applies to you,
  from the supervisory authority of the EU country where you live or work.

**How to use them.** Most rights work directly in the app, at once: see what
the server holds about your account; turn off search by name; revoke any
contact's delivery token; delete the account — see
[Deleting your account](ACCOUNT-DELETION.md). All we know about you is your
account keys, so a request from the app is signed by your device — that is how
we know it is yours. We answer written requests within 10 working days, or
sooner if the law of your country sets a shorter time. A refusal always states
its reasons.

## 10. Age

LUME is not meant for anyone under 16. If the law of your country sets a higher
age at which you can consent to the processing of personal data on your own,
that age applies, and below it you may use LUME only with the consent of your
legal representative. An account we learn belongs to a child below that age is
deleted.

## 11. The website

The LUME website uses no cookies, analytics or scripts — see
[Privacy on the website](WEBSITE.md).

## 12. Changes

We announce material changes to this policy in the app at least 15 calendar
days before they take effect. If a change needs new consent, we ask for it,
and without it we keep processing data on the previous terms or delete it. The
document's history is public in our repository.

## 13. Language versions

This policy is made in Kazakh, Russian and English. The Kazakh and Russian
texts have equal force; if they differ, the Russian text applies. The English
text is a translation for convenience.
