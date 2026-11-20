<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME Privacy Policy

**Status: draft.** Takes effect on the day the first public LUME build is
released; this line will then be replaced by that date.

This document is LUME Inc.'s policy on the collection, processing and
protection of personal data within the meaning of article 25(2) sub-paragraph
1-1) of Law of the Republic of Kazakhstan No. 94-V "On Personal Data and Their
Protection" (the "Kazakh law"). It also gives the information owed under
articles 13 and 14 of the EU General Data Protection Regulation (the "GDPR") to
the people the GDPR applies to.

In this policy, "LUME" means the official LUME apps and the relay server
through which they deliver encrypted messages; "the server" means that relay
server; "you" means a person who uses LUME; and "we" means LUME Inc. The
consent you give when you create an account is set out in
[Consent to the Collection and Processing of Personal Data](CONSENT.md). Using
LUME is also governed by the [Terms of Use](TERMS.md).

## 1. Who we are

1. The owner and operator of the database in which LUME users' personal data
   is processed (the server) is **LUME Inc.** (ТОО «LUME Inc.»), a limited
   liability partnership registered in the Republic of Kazakhstan, BIN
   260740032421, Temirtau, Karaganda Region. For the GDPR, LUME Inc. is the
   controller.
2. LUME Inc. appoints, by order of its director, a person responsible for
   organising the processing of personal data. That person oversees our compliance with the
   law on personal data and handles requests from data subjects, including
   requests under the GDPR. Reach that person at the personal-data address on
   the [contact page](CONTACT.md).

> [!IMPORTANT]
> **To be filled in before release.** The address for personal-data requests;
> the representative in the European Union under GDPR article 27; and whether a
> data protection officer is designated under GDPR article 37. See the
> [contact page](CONTACT.md).

Until those addresses are published, use private reports at
[github.com/lumeincc/lume](https://github.com/lumeincc/lume). Please do not
post personal data in public issues.

## 2. In short

LUME is built to know no more about you than it needs to deliver your
messages.

- We **cannot read** your messages, attachments or contact list: they are
  encrypted on your device, and we hold no keys that decrypt them. The one
  exception is a **report**: if someone you wrote to reports your messages, the
  app sends us those messages as that person received them, sealed so that
  only we can open them (section 3).
- We **do not ask** for your phone number, e-mail, name, address book or
  location.
- We **do not store who sent a message.** For a message waiting to be
  delivered, the server records whom it is for, not whom it is from.
- The apps contain **no ads, analytics, trackers** or third-party SDKs.
- We **do not sell or share** data for advertising, and we do no profiling.

## 3. What the server stores, why and for how long

This is the complete list of the kinds of personal data the server stores. It
is the list of personal data necessary and sufficient for LUME within the
meaning of article 25(2) sub-paragraph 1) of the Kazakh law.

| Data | Why | How long |
|---|---|---|
| **Your username**, which you choose | so people can find you and check that a name belongs to your keys. While search by name is on, anyone can look you up by your username. While it is off, only people who hold an invite from you or who are already your contacts can. Anyone can always check whether a username is taken | until you delete the account, or 365 days without the app connecting |
| **A random account identifier**, assigned by the server | to address messages, attachments and requests for your keys without using your username | the same |
| **Your account's public keys and their signatures**: the identity keys and the signature that binds them, the device key, and the signed and one-time keys others use to start a conversation with you (prekeys), each with its number and the time it was created | so others can start an encrypted conversation with you, and the server can check that requests come from your device; public keys decrypt nothing | the same; a one-time key is deleted when it is handed out or your app withdraws it, a signed key when a newer one replaces it, and a previous device's keys when you recover the account on a new device |
| **The account's generation number**, which counts how many times the account was recovered on a new device | to disconnect the old device after a recovery | the same |
| **The discoverability setting** | whether you can be found by name | the same |
| **The day the account was created and the day it last connected**, as dates without a time | to delete abandoned accounts after 365 days, and to apply the stricter limits for accounts younger than 7 days | the same |
| **Records that one-time keys were handed out**: which key, a sequence number and the day, nothing about who asked for it | so the app can top up its stock of keys and not keep spare ones | 15 days |
| **Delivery tokens**: random values your app issues to each contact and keeps in reserve for new ones. Only their hashes are stored, each with its state (live, blocked, or left over from a previous device) and the day it was created and last used | to accept messages from your contacts, and to discard a blocked contact's messages without telling them, without knowing who your contacts are | a live token until your app replaces it (tokens are replaced about every 30 days) or you delete the account. **A blocked contact's token stays, as a sink that discards their messages, until you delete the account.** A token left over from a previous device is deleted if it goes unused for 45 days |
| **Invite codes**: hashes only, each with its expiry time | so people you choose can reach you while search by name is off | 24 hours, or until you revoke the invite or recover the account on a new device |
| **Messages awaiting delivery**, encrypted and unreadable to us. Each is stored with the account it is for, the generation it was sealed for, the time it arrived (to the second), and how it arrived: the hash of the delivery token it came with; or, for a message from someone who has no token, the hash of the invite used; or, **for a message from a stranger without an invite**, a hash of the network it was sent from (section 4) | to hand them to you when you next connect, and to keep one network from filling your queue | deleted as soon as your app confirms it has them, and in any case after 30 days. Also deleted when you recover the account on a new device, and earlier if newer messages push it out of a full queue or the server runs short of disk space |
| **Attachments**, encrypted and unreadable to us, each with its identifier, its size, the account it is for, a hash of the key that authorised its upload, how many downloads are left and its expiry time | so the recipient can download them | until the download limit is used up, and for at most 30 days; earlier if the server runs short of disk space |
| **Reports** by other users about messages you sent: the reported messages as the reporter received them and your identity keys, sealed so that only LUME Inc. can open them, with the time the report arrived (to the second). The server does not record which account sent a report | to act on abuse ([Terms of Use](TERMS.md), section 6) and to meet legal duties | 90 days, or longer where the law requires the report to be kept. The server cannot open a report to see whom it concerns, so deleting an account does not delete reports about it |
| **Held and barred usernames**: a hash of the name, whether it is held or barred, and the day the hold or bar ends | so a freed name cannot be taken at once by someone posing as its former holder, and a name barred for abuse cannot be registered again | a freed name, 31 days; a barred name, while the bar lasts. The list keeps at most 100,000 names, and the oldest are removed first when it is full |

The certificate that vouches for your username is signed when it is needed and
kept in a cache until the end of that day, not in the database.

**Preservation.** Where the law requires it, where a competent authority
lawfully asks us to, or where we report child sexual exploitation or a threat
to life ([Law Enforcement Policy](LAW-ENFORCEMENT.md),
[Child Safety Standards](CHILD-SAFETY.md)), we may keep specific data from this
list beyond the periods above. We keep it only for as long as the law requires
or permits, and only for that purpose.

## 4. What passes through the server but is not stored

- **IP address and connection time.** The server needs them to reach your
  device. It also uses them in memory against abuse: to limit how many
  connections, registrations and messages to strangers one address or network
  may make, to set the proof of work it asks for, and to apply the stricter
  limits for accounts younger than 7 days. **They are never written to disk or
  to logs.** The rate-limit counters are kept in memory, in tables of fixed
  size from which old entries are dropped.
- **A hash of the sender's network, for a message from a stranger without an
  invite.** When someone who has neither a delivery token from you nor an
  invite writes to you, a hash of their network (the /48 IPv6 or /24 IPv4
  block), keyed with a key that changes every day, is kept with the message. It
  only stops one network from filling your queue. The address cannot be
  recovered from it, and it is deleted with the message.
- **Delivery tokens and invite codes themselves.** The server sees a token or
  invite code whenever a request presents it, and stores only its hash.
- **Typing indicators and online status** are encrypted like any other message.
  They are passed on only while you are connected; if you are offline they are
  dropped, never stored. Delivery receipts are ordinary encrypted messages and
  wait for you like any other.
- **Service logs** hold event names, counts, durations and error codes. They
  hold no usernames, account identifiers, tokens, addresses or message content.

**What the server never stores:** who sent a message; group names, members or
roles; display names and profile photos; typing and read state; the signatures
and one-time values of requests; IP addresses.

**What no server can technically hide.** While a connection is open, the
server sees its address. Someone watching the server live could correlate
incoming and outgoing connections by address and timing. We do not record any
of this; if it matters to you, use Tor or a VPN. Details are in section 1 of
the [cryptography specification](../docs/CRYPTO.md).

## 5. What stays on your device

Messages, contacts, contact names, profile photos, keys and settings are stored
**only on your device**, in an encrypted vault. We have no copy. The vault's
key is derived from your passphrase and, where the device supports it, from a
key held in secure hardware:

- **on Android**, a key in the Android Keystore that cannot leave it;
- **on Windows**, a key in the computer's TPM 2.0 that cannot leave it.

Where the device has no usable secure hardware, the app tells you so and works
in software-only mode: a random secret kept by the operating system takes the
hardware key's place (on Windows, protected with DPAPI for your user account;
on Android, in the app's private storage), and the app asks for a longer
passphrase. Section 10 of the [cryptography specification](../docs/CRYPTO.md)
describes this per platform.

The apps keep this data out of Android cloud backup and device-to-device
transfer, and out of Windows roaming, so it does not reach Google or Microsoft
either.

Your **recovery phrase**, 24 words, is shown once, on your device. We never
receive it and cannot recover it.

## 6. Purposes and grounds for processing

1. **Under the Kazakh law**, the ground for all the processing in sections 3
   and 4 is your consent to the collection and processing of personal data,
   which you give in the app when you create an account. Its text is in
   [Consent to the Collection and Processing of Personal Data](CONSENT.md).
   Without consent, we process data only in the cases listed in article 9 of
   the Kazakh law, such as fulfilling the lawful requirements of courts and law
   enforcement bodies.
2. **Under the GDPR**, where it applies to you, we do not rely on consent. The
   consent you give under the Kazakh law does not change the grounds below.
3. We process the data only for the purposes below, and for no other purpose,
   such as advertising, analytics or profiling.

| Purpose | Data (section 3 and 4) | Ground under the Kazakh law | Ground under the GDPR |
|---|---|---|---|
| Creating and keeping your account; letting people find you and check your keys | username, account identifier, public keys, generation number, discoverability setting, the day the account was created | consent | performance of the contract, the [Terms of Use](TERMS.md) (article 6(1)(b)) |
| Delivering messages and attachments; recovering the account on a new device | public keys, records of handed-out keys, delivery tokens, invite codes, messages and attachments awaiting delivery, the day the account last connected, IP address in memory | consent | performance of the contract (article 6(1)(b)) |
| Protecting the service and its users from spam, flooding, account farming and impersonation | IP address in memory, the hash of a stranger's network, the days an account was created and last connected, proof of work, held usernames | consent | legitimate interest (article 6(1)(f)): keeping LUME available and free of spam for everyone without identifying anyone |
| Acting on reports and enforcing the [Terms of Use](TERMS.md) | reports, account data, barred usernames | consent | legitimate interest (article 6(1)(f)): protecting users, enforcing the Terms and establishing, exercising or defending legal claims |
| Meeting legal duties: answering lawful requests, preserving data, reporting child sexual exploitation | the data in section 3 that the duty concerns | the cases in article 9 of the Kazakh law, and consent | legal obligation under EU or Member State law (article 6(1)(c)); otherwise legitimate interest in complying with the law of the Republic of Kazakhstan that applies to us (article 6(1)(f)) |
| Preventing a threat to someone's life or of serious harm to their health | the data in section 3 that the threat concerns | the cases in article 9 of the Kazakh law | vital interests (article 6(1)(d)) |
| Answering your requests about your data | what the request concerns | the duties of an operator under articles 24 and 25 of the Kazakh law | legal obligation (article 6(1)(c)) |

4. Giving the data in section 3 is necessary to create and use an account. No
   law requires you to give it, but without it we cannot provide LUME.
5. **Objection.** Where the GDPR applies to you, you may object to processing
   based on legitimate interest (GDPR article 21). We then stop it unless we
   have compelling legitimate grounds that override your interests, or need
   the data for legal claims. Most protective measures apply to every account
   alike; if we cannot stop one for you alone, deleting the account ends it,
   except for the data listed in section 9.
6. **Automated decisions.** We make no decisions about you based solely on
   automated processing that have legal effects for you or similarly affect
   you. The only automated measures are rate limits, storage quotas, the
   removal of the oldest messages from a full queue, and the proof of work
   asked for at registration and for every message sent on the introduction
   lane, that is, to someone who has not yet given the sender a delivery token.
   They slow down or refuse requests for a time and do not assess you as a
   person. Restricting or deleting an account, or barring a username, is
   decided by people at LUME Inc.
7. LUME has **no recommender system**: it does not choose or rank what you see.

## 7. Who else is involved

- **The hosting provider.** The server runs on rented infrastructure in a data
  centre in the Republic of Kazakhstan. The provider processes data only on our
  instructions and under contract. Its network carries connections to the
  server and so sees their addresses, but the server itself decrypts the
  connection, so the provider sees nothing else in transit. Messages and
  attachments stored on its equipment are end-to-end encrypted.
- **Other LUME users.** Whoever looks you up as described in section 3
  receives your username, your public keys and the certificate that links
  them, which also shows your generation number. Your contacts receive what you
  send them.
- **App stores.** The store you installed LUME from handles downloads, updates
  and any statistics it collects under its own rules, as an independent
  controller. We receive nothing from a store that identifies you or links to
  your LUME account.
- **Public authorities**, only in the cases and to the extent described in the
  [Law Enforcement Policy](LAW-ENFORCEMENT.md), and only data listed in
  section 3, because we have nothing else.
- **A successor.** If LUME Inc. is reorganised or transfers the service to a
  successor that keeps providing LUME, the data in section 3 passes to that
  successor. We transfer it only to a successor that takes on this policy, we
  tell you in the app before the transfer, and you can delete your account
  before it happens.
- **No one else.** We use no ad networks, analytics, crash reporting or push
  services that would receive your data, and we do not share data for
  marketing.

**Where the data is.** The server and all the data listed in section 3 are in a
data centre in the Republic of Kazakhstan, as article 12(2) of the Kazakh law
requires. There is no cross-border transfer: the data of users in any country
is collected directly by their apps and stored in Kazakhstan.

> [!IMPORTANT]
> **To be filled in before release.** The name of the hosting provider and its
> data centre, and the contract under which it processes data on behalf of
> LUME Inc.

## 8. How we protect data

- **End-to-end encryption** with a hybrid post-quantum key exchange: messages
  and attachments on the server are encrypted under keys we do not have. Only
  reports are sealed to a key LUME Inc. holds. The design is in
  [docs/CRYPTO.md](../docs/CRYPTO.md); the source code is open.
- **Encrypted connections:** the apps reach the server only over TLS, which
  the server itself terminates.
- **Minimisation:** the server holds only what section 3 lists, for limited
  periods. Tokens, invites, upload keys and held or barred names are stored as
  hashes. A hash keeps the original value out of the database; it does not
  stop someone who guesses a value, such as a username, from checking the
  guess. The days an account was created and last connected, and the days a
  token was created and last used, are recorded without a time.
- **Deletion without remnants:** the server's database is configured to
  overwrite deleted records instead of leaving them in the file.
- **Access:** only staff of LUME Inc. who need it for their duties, on a list
  the director approves, can access the server. The key that signs usernames
  is held by a separate signer, a hardware security module or a separate
  process, so that breaking into the server's network-facing process does not
  give it away.
- **Review:** the code and the specifications are public so that anyone can
  check them. No independent security audit has been completed yet.

No system is completely secure, and we do not promise that a breach can never
happen. We do promise to act on one as follows.

**If a breach happens.** If we discover a breach of personal-data security, we
will:

- notify the authorised body of the Republic of Kazakhstan for personal-data
  protection within the time the law sets, no later than one working day after
  discovery, giving the contact details of the person responsible for
  organising the processing of personal data;
- notify the competent EU supervisory authority within 72 hours where the
  breach affects people the GDPR applies to, unless it is unlikely to create a
  risk for them;
- tell you without undue delay, in the app and on the website, what happened,
  which data is affected and what to do, where the breach may affect your
  rights or the law requires us to tell you.

## 9. Your rights

1. You have the right to:
   - **know**, free of charge, whether we hold personal data about you, and
     get a copy of it and information about the purposes, sources, ways and
     periods of processing (GDPR article 15);
   - **have it changed or completed** if it is inaccurate or incomplete
     (GDPR article 16);
   - **have it blocked, erased or destroyed** where the law allows, including
     where it was collected or processed unlawfully, and to restrict
     processing (GDPR articles 17 and 18);
   - **receive the data you gave us** in a machine-readable form
     (portability, GDPR article 20);
   - **object** to processing based on legitimate interest (section 6);
   - **give or refuse consent** to your data being published in publicly
     available sources; we publish none;
   - **withdraw consent** under the Kazakh law, by deleting the account;
   - **compensation** for harm caused by a breach of the law on personal data,
     as the law provides;
   - **seek protection** from the authorised body for personal-data protection
     of the Republic of Kazakhstan or a court and, where the GDPR applies to
     you, lodge a complaint with the supervisory authority of the EU country
     where you live or work or where the alleged breach took place (GDPR
     article 77). You do not have to contact us first.
2. **Withdrawing consent by deleting the account** ends processing at once,
   although the Kazakh law allows up to 15 working days. Only the following
   is kept, for the periods in section 3:
   - reports about your messages, which the server cannot link to an account;
   - the hash of your username, held for 31 days, or kept while a bar lasts if
     the name was barred for abuse;
   - messages you sent that are still waiting for delivery to others, which
     the server cannot link to you;
   - data that the law requires us to keep or that a competent authority has
     lawfully asked us to preserve (section 3).

   Withdrawal does not affect processing before it, or processing the law
   allows without consent.
3. **In the app**, at once: you can see what the server holds about your
   account, turn off search by name, block a contact, which turns that
   contact's delivery token into a sink, and delete the account (see
   [Deleting your account](ACCOUNT-DELETION.md)).
4. **In writing**, at the personal-data address on the
   [contact page](CONTACT.md), in Kazakh, Russian or English. The server holds
   no name, phone number or e-mail address for you, only the username, the
   account identifier, the dates and the keys listed in section 3. So we can
   act on a request about a specific account only if it is made from that
   account in the app or is otherwise signed with that account's key. If we
   cannot confirm that an account is yours, we tell you so and why (GDPR
   articles 11 and 12(2)).
5. We answer a request within the period the law sets, and in any case within
   10 working days of receiving it. Where the Kazakh law requires us to
   change, block or delete data within one working day, we do so. Requests are
   free. Where the GDPR applies and a request is manifestly unfounded or
   excessive, we may refuse it (GDPR article 12(5)). A refusal always states
   its reasons and how to challenge it.

> [!IMPORTANT]
> **To be filled in before release.** The name and website of the authorised
> body for personal-data protection of the Republic of Kazakhstan.

## 10. Age

1. LUME is not meant for anyone under 16. If the law of your country sets a
   higher age at which you can consent to the processing of personal data on
   your own, that age applies, and below it you may use LUME only with the
   consent of your legal representative.
2. LUME collects no data that would show a user's age, so it cannot check it.
   The app asks you to confirm your age before it creates an account.
3. If we learn that an account belongs to someone under 16, or to someone
   below the higher age without the consent of a legal representative, we
   delete it.

## 11. The website

The LUME website sets no cookies, stores nothing on your device and uses no
analytics. See [the website page](WEBSITE.md).

## 12. Changes

1. We change this policy when the law, LUME's features or protocol, or our
   security measures change, or to make it clearer.
2. We announce material changes in the app at least 15 calendar days before
   they take effect. If a change needs new consent, we ask for it, and without
   it we keep processing data on the previous terms or delete it. If you do not
   accept a change, you can delete your account at any time, free of charge.
3. Changes that only correct or clarify the text, without changing what we
   process or why, take effect when published.
4. Every version of this document is kept in the public history of our
   repository.

## 13. Language

This policy is published in English.
