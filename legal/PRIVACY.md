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
server; "you" means a person who uses LUME; and "we" means LUME Inc. Software
other than the official apps may also connect to the server if it follows the
LUME protocol, under the [Terms of Use](TERMS.md). This policy covers what the
server and LUME Inc. do with your data whatever software you use; what other
software does on your device is the responsibility of its maker. The consent
you give when you create an account is set out in
[Consent to the Collection and Processing of Personal Data](CONSENT.md). Using
LUME is also governed by the [Terms of Use](TERMS.md).

## 1. Who we are

1. The owner and operator of the database in which LUME users' personal data
   is processed (the server) is **LUME Inc.** (ТОО «LUME Inc.»), a limited
   liability partnership registered in the Republic of Kazakhstan, BIN
   260740032421, Temirtau, Karaganda Region. For the GDPR, LUME Inc. is the
   controller.
2. LUME Inc. appoints, by order of its director, a person responsible for
   organising the processing of personal data. That person oversees our
   compliance with the law on personal data and handles requests from data
   subjects, including requests under the GDPR. Reach that person at the
   personal-data address on the [contact page](CONTACT.md).

> [!IMPORTANT]
> **To be filled in before release.** The address for personal-data requests;
> the representative in the European Union under GDPR article 27; and whether a
> data protection officer is designated under GDPR article 37. See the
> [contact page](CONTACT.md).

Until those addresses are published, LUME has not been released and LUME Inc.
holds no personal data about LUME users. Until then, the only online channel,
GitHub private vulnerability reporting at
[github.com/lumeincc/lume](https://github.com/lumeincc/lume), is for
vulnerabilities only ([SECURITY.md](../SECURITY.md)). Please do not send
personal data through it, and do not post personal data in public issues.
Claims, requests about personal data and any other formal communication may be
sent by post to the registered office of LUME Inc. in Temirtau; its address is
recorded in the state database "Legal Entities" of the Republic of Kazakhstan
under BIN 260740032421 and can be obtained through the eGov portal as
information about a registered legal entity (see the
[contact page](CONTACT.md)). What LUME Inc. does with what you send in such a
letter is described in section 4.4 of the [website page](WEBSITE.md).

## 2. In short

LUME is built to know no more about you than it needs to deliver your
messages.

- We **cannot read** your messages, attachments or contact list: they are
  encrypted on your device, and we hold no keys that decrypt them. The one
  exception is a **report**: if someone you wrote to reports your messages, the
  app sends us those messages as that person received them, sealed so that
  only we can open them (section 3).
- We **do not ask** for your phone number, e-mail, name, address book or
  location to create or use an account. If you write to us, we receive what
  you choose to send (section 12).
- We **do not store who sent a message.** For a message waiting to be
  delivered, the server records whom it is for, not whom it is from.
- The official apps contain **no ads, analytics, trackers** or third-party
  SDKs.
- We **do not sell or share** data for advertising, and we do no profiling.

## 3. What the server stores, why and for how long

This is the complete list of the kinds of personal data the server stores.
Together with section 12, which covers the personal data LUME Inc. holds
outside the server, it is the list of personal data necessary and sufficient
for LUME within the meaning of article 25(2) sub-paragraph 1) of the Kazakh
law. The list that the director of LUME Inc. approves by order under that
article is the same.

| Data | Why | How long |
|---|---|---|
| **Your username**, which you choose | so people can find you and check that a name belongs to your keys. While search by name is on, anyone can look you up by your username. While it is off, only people who hold an invite from you or who are already your contacts can. Anyone can always check whether a username is taken | until you delete the account, or 365 days without the app connecting |
| **A random account identifier**, assigned by the server | to address messages, attachments, notices and requests for your keys without using your username | the same |
| **Your account's public keys and their signatures**: the identity keys and the signature that binds them, the device key, and the signed and one-time keys others use to start a conversation with you (prekeys), each with its number and the time it was created | so others can start an encrypted conversation with you, and the server can check that requests come from your device; public keys decrypt nothing | the same; a one-time key is deleted when it is handed out or your app withdraws it, a signed key when a newer one replaces it, and a previous device's keys when you recover the account on a new device |
| **The account's generation number**, which counts how many times the account was recovered on a new device | to disconnect the old device after a recovery | the same |
| **The discoverability setting** | whether you can be found by name | the same |
| **The day the account was created and the day it last connected**, as dates without a time | to delete abandoned accounts after 365 days, and to apply the stricter limits for accounts younger than 7 days | the same |
| **The version of the documents you accepted, and the day**: the number of the version of the [Terms of Use](TERMS.md), this policy and the [Consent](CONSENT.md) that you accepted, when you created the account or later, and the day you accepted it. The server keeps the number and the day, not the signature of the request that carried them | to record and prove your acceptance of the Terms and your consent (article 25(2) sub-paragraph 5) of the Kazakh law), and to ask you to accept a new version when one takes effect | the same; replaced when you accept a later version |
| **A measure on the account**: whether the account is restricted or suspended under section 6 of the [Terms of Use](TERMS.md), and the day the measure ends | so the server can apply a measure that people at LUME Inc. decided ([Terms of Use](TERMS.md), section 6) | while the measure lasts, and at most until the account is deleted |
| **Notices waiting for you**: the kind of each notice from LUME Inc. and the day it was issued, with the account it is for. A notice carries no text; the app shows its own text and links to the full text on our website | so you receive a notice even if your app was offline when it was issued | until it is delivered to your app, and at most 30 days; at most 20 per account |
| **Records that one-time keys were handed out**: which key, a sequence number and the day, nothing about who asked for it | so the app can top up its stock of keys and not keep spare ones | 15 days |
| **Delivery tokens**: random values your app issues to each contact and keeps in reserve for new ones. Only their hashes are stored, each with its state (live, blocked, or left over from a previous device) and the day it was created and last used | to accept messages from your contacts, and to discard a blocked contact's messages without telling them, without knowing who your contacts are | a live token until your app replaces it (tokens are replaced about every 30 days) or you delete the account. **A blocked contact's token stays, as a sink that discards their messages, until you delete the account.** A token left over from a previous device is deleted if it goes unused for 45 days |
| **Invite codes**: hashes only, each with its expiry time | so people you choose can reach you while search by name is off | 24 hours, or until you revoke the invite or recover the account on a new device |
| **Messages awaiting delivery**, encrypted and unreadable to us. Each is stored with the account it is for, the generation it was sealed for, the time it arrived (to the second), and how it arrived: the hash of the delivery token it came with; or, for a message from someone who has no token, the hash of the invite used; or, **for a message from a stranger without an invite**, a hash of the network it was sent from (section 4) | to hand them to you when you next connect, and to keep one network from filling your queue | deleted as soon as your app confirms it has them, and in any case after 30 days. Also deleted when you recover the account on a new device, and earlier if newer messages push it out of a full queue or the server runs short of disk space |
| **Attachments**, encrypted and unreadable to us, each with its identifier, its size, the account it is for, a hash of the key that authorised its upload, how many downloads are left and its expiry time | so the recipient can download them | until the download limit is used up, and for at most 30 days; earlier if the server runs short of disk space |
| **Reports** by other users about messages you sent: the reported messages as the reporter received them and your identity keys, sealed so that only LUME Inc. can open them, with the time the report arrived (to the second). The server does not record which account sent a report | to act on abuse ([Terms of Use](TERMS.md), section 6) and to meet legal duties | 90 days. The server cannot open a report to see whom it concerns, so deleting an account does not delete reports about it. Where the law requires a report to be kept longer, we keep a copy as preserved evidence (section 12) |
| **Held and barred usernames**: a hash of the name, whether it is held or barred, and the day the hold or bar ends | so a freed name cannot be taken at once by someone posing as its former holder, and a name barred for abuse cannot be registered again | a freed name, 31 days; a barred name, while the bar lasts. The list keeps at most 100,000 names, and the oldest are removed first when it is full |

The certificate that vouches for your username is signed when it is needed and
kept in a cache until the end of that day, not in the database.

**Preservation.** Where the law requires it, where a competent authority
lawfully asks us to, where we delete an account for, or report, child sexual
exploitation, or where we report a threat to life
([Law Enforcement Policy](LAW-ENFORCEMENT.md),
[Child Safety Standards](CHILD-SAFETY.md)), we may keep a copy of specific data
from this list beyond the periods above, as section 12 describes. We keep it
only for as long as the law requires or permits, and only for that purpose.

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

This section describes the official apps. Messages, contacts, contact names,
profile photos, keys and settings are stored **only on your device**, in an
encrypted vault. We have no copy. The vault's key is derived from your
passphrase and, where the device supports it, from a key held in secure
hardware:

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

1. **Under the Kazakh law**, the ground for the processing in section 3, and
   in section 4 once you have an account, is your consent to the collection
   and processing of personal data, which you give when you create an
   account: by pressing *I accept* in the app, or, if you use other software,
   by registering the account with it. Its text is in
   [Consent to the Collection and Processing of Personal Data](CONSENT.md).
   Without consent, we process data only in the cases listed in article 9 of
   the Kazakh law, such as fulfilling the lawful requirements of courts and law
   enforcement bodies. Section 12 gives the grounds for the data we receive
   outside the server.
2. **Under the GDPR**, where it applies to you, we do not rely on consent. The
   consent you give under the Kazakh law does not change the grounds below.
   For users in the European Union, LUME is also an electronic communications
   service, so the confidentiality of communications and the processing of
   traffic data, such as IP addresses, the hash of a stranger's network and
   delivery tokens, are also governed by the ePrivacy Directive (2002/58/EC) as
   implemented in the Member State concerned. We process traffic data only to
   transmit communications and for the security of the service.
3. We process the data only for the purposes below, and for no other purpose,
   such as advertising, analytics or profiling.

| Purpose | Data (sections 3, 4 and 12) | Ground under the Kazakh law | Ground under the GDPR |
|---|---|---|---|
| Creating and keeping your account; letting people find you and check your keys | username, account identifier, public keys, generation number, discoverability setting, the day the account was created | consent | performance of the contract, the [Terms of Use](TERMS.md) (article 6(1)(b)) |
| Recording which version of the Terms of Use, this policy and the Consent you accepted | the version number and the day of acceptance | consent; the record also serves our duty to prove consent (article 25(2) sub-paragraph 5)) | performance of the contract (article 6(1)(b)); legitimate interest in being able to prove what you accepted (article 6(1)(f)) |
| Delivering messages and attachments; recovering the account on a new device | public keys, records of handed-out keys, delivery tokens, invite codes, messages and attachments awaiting delivery, the day the account last connected, IP address in memory | consent | performance of the contract (article 6(1)(b)) |
| Sending you notices from LUME Inc. | account identifier, the kind and day of each notice waiting for you | consent; where a law requires the notice, also the cases in article 9 | performance of the contract (article 6(1)(b)); where EU or Member State law requires the notice, legal obligation (article 6(1)(c)) |
| Protecting the service and its users from spam, flooding, account farming and impersonation | IP address in memory, the hash of a stranger's network, the days an account was created and last connected, proof of work, held usernames | consent; after the account is deleted, for the held username, the cases in article 9 of the Kazakh law | legitimate interest (article 6(1)(f)): keeping LUME available and free of spam for everyone without identifying anyone |
| Acting on reports and enforcing the [Terms of Use](TERMS.md) | reports, account data, the measure on the account and the day it ends, barred usernames | consent; after the account is deleted, for what section 9.2 keeps, the cases in article 9 and article 8(2) of the Kazakh law | legitimate interest (article 6(1)(f)): protecting users, enforcing the Terms and establishing, exercising or defending legal claims |
| Meeting legal duties: answering lawful requests, preserving data, reporting child sexual exploitation | the data in sections 3 and 12 that the duty concerns | the cases in article 9 of the Kazakh law, and consent | legal obligation under EU or Member State law (article 6(1)(c)); otherwise legitimate interest in complying with the law of the Republic of Kazakhstan that applies to us (article 6(1)(f)) |
| Preventing a threat to someone's life or of serious harm to their health | the data in sections 3 and 12 that the threat concerns | the cases in article 9 of the Kazakh law | vital interests (article 6(1)(d)) |
| Answering your requests about your data | what the request concerns | the duties of an operator under articles 24 and 25 of the Kazakh law | legal obligation (article 6(1)(c)) |
| Dealing with what people send us outside the server, with the reports we open and with the record of measures we take | the data in section 12 | as section 12 sets out | as section 12 sets out |

4. Giving the data in section 3 is necessary to create and use an account. No
   law requires you to give it, but without it we cannot provide LUME.
5. **Objection.** Where the GDPR applies to you, you may object to processing
   based on legitimate interest (GDPR article 21). We then stop it unless we
   have compelling legitimate grounds that override your interests, or need
   the data for legal claims. Most protective measures apply to every account
   alike; if we cannot stop one for you alone, deleting the account ends it,
   except for the data listed in section 9.2.
6. **Automated decisions.** Apart from deleting data when the periods in
   section 3 end, and refusing requests that the protocol does not allow, the
   only things the server does automatically are the same as in clause 6.7 of
   the [Terms of Use](TERMS.md):
   1. rate limits and storage quotas, including the stricter ones for
      accounts younger than 7 days;
   2. the proof of work asked for at registration and for every message sent
      to someone who has not yet given the sender a delivery token;
   3. the removal of the oldest waiting messages and attachments when a queue
      is full or the server is near its storage limit;
   4. refusing, for a time, to store more for the accounts that hold the most
      while the server is near its storage limit;
   5. the deletion of an account after 365 days without the app connecting to
      the server, after which its username is held as section 3 describes.

   The first four slow down, refuse or remove data under fixed rules and do
   not assess you as a person. The fifth is a fixed rule, announced in
   advance, that applies to every account alike and does not assess you or
   your content. It is necessary for the contract (GDPR article 22(2)(a)), and
   you avoid it by letting your app connect at least once in 365 days. You may
   ask a person at LUME Inc. to review any of them, at the address for appeals
   on the [contact page](CONTACT.md). Warnings, restrictions, suspensions,
   deletions and bars of a username for a breach of the Terms of Use are
   decided by people at LUME Inc., and the server only applies them.
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
  them, which also shows your account identifier and generation number. Your
  contacts receive what you send them.
- **App stores.** The store you installed LUME from handles downloads, updates
  and any statistics it collects under its own rules, as an independent
  controller. We receive nothing from a store that identifies you or links to
  your LUME account.
- **Public authorities and recognised bodies**, only in the cases and to the
  extent described in the [Law Enforcement Policy](LAW-ENFORCEMENT.md) and the
  [Child Safety Standards](CHILD-SAFETY.md), and only the data listed in
  section 3 and the data in section 12 that the request or report concerns,
  because we have nothing else.
- **GitHub, Inc. (USA)**, which holds what researchers send through GitHub
  private vulnerability reporting, under its own terms (section 12). When a
  vulnerability is in a third-party library, we tell the researcher first and
  then give the library's maintainers only its technical details, never
  anything that identifies the researcher.
- **A successor.** If LUME Inc. is reorganised or transfers the service to a
  successor that keeps providing LUME, the data in sections 3 and 12 passes to
  that successor. We transfer it only to a successor that takes on this
  policy, we tell you by a notice in the app at least 15 calendar days before
  the transfer, and you can delete your account before it happens.
- **No one else.** We use no ad networks, analytics, crash reporting or push
  services that would receive your data, and we do not share data for
  marketing.

**Where the data is.** The server and all the data listed in section 3 are in a
data centre in the Republic of Kazakhstan, as article 12(2) of the Kazakh law
requires. Section 12 says where the data we receive outside the server is
kept. There is no routine cross-border transfer: the apps of users in every
country send data directly to the server in Kazakhstan. We transfer personal
data abroad only:

1. to a foreign competent authority, through international legal assistance
   under a treaty of the Republic of Kazakhstan;
2. to a foreign competent authority or a recognised body, when we report child
   sexual exploitation or a threat to life, as the law requires or allows;
3. where another law binding on LUME Inc. requires it; and
4. where a person chooses to send us something through GitHub private
   vulnerability reporting, which GitHub, Inc. (USA) holds under its own
   terms, on the consent the sender gives by sending it.

In each case we transfer only the data that the case requires, and only as
article 16 of the Kazakh law permits. How we answer authorities is described
in the [Law Enforcement Policy](LAW-ENFORCEMENT.md) and the
[Child Safety Standards](CHILD-SAFETY.md).

> [!IMPORTANT]
> **To be filled in before release.** The name of the hosting provider and its
> data centre, and the contract under which it processes data on behalf of
> LUME Inc.; and a lawyer's confirmation that a person who sends something
> through GitHub private vulnerability reporting gives the consent to its
> transfer abroad that article 16 of the Kazakh law requires (item 4).

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
- tell you without undue delay, where the breach may affect your rights or the
  law requires us to tell you: by a notice in the app, which links to the full
  text on our website, and in that text say what happened, which data is
  affected and what to do. Where the breach affects the data in section 12,
  we also tell the people concerned at the contact details they gave us.

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
     available sources; we publish none, except that the publication of a
     fixed vulnerability names the researcher who reported it if, and only
     if, they ask to be credited (section 12);
   - **withdraw consent** under the Kazakh law: for the data in sections 3
     and 4, by deleting the account; for what you sent us outside the server
     (section 12), by writing to us, after which we keep it only where the law
     allows without consent;
   - **compensation** for harm caused by a breach of the law on personal data,
     as the law provides;
   - **seek protection** from the authorised body for personal-data protection
     of the Republic of Kazakhstan or a court and, where the GDPR applies to
     you, lodge a complaint with the supervisory authority of the EU country
     where you live or work or where the alleged breach took place (GDPR
     article 77). You do not have to contact us first.
2. **Withdrawing consent by deleting the account** ends processing at once,
   although the Kazakh law allows up to 15 working days. Only the following
   is kept, for the periods in sections 3 and 12:
   - reports about your messages, which the server cannot link to an account;
   - the hash of your username, held for up to 31 days, or kept while a bar
     lasts if the name was barred for abuse;
   - messages and attachments you sent that are still waiting for delivery to
     others, which the server cannot link to you;
   - data that the law requires us to keep or that a competent authority has
     lawfully asked us to preserve (section 12);
   - what you sent to us outside the server, and the other data in
     section 12, for the periods given there.

   Withdrawal does not affect processing before it, or processing the law
   allows without consent. We keep what this point lists after you withdraw
   consent only in the cases in article 9 of the Kazakh law, or where article
   8(2) of that law does not allow consent to be withdrawn, and, for the data
   in section 12, on the grounds given there.
3. **In the app**, at once: you can see the main data the server holds about
   your account (your username and account identifier, whether search by name
   is on, the days the account was created and last connected, the version of
   the documents you accepted and the day, any measure on the account and the
   day it ends, the generation number, and how many delivery tokens, invites,
   waiting messages and attachments are stored). You can also turn off search
   by name, block a contact, which turns that contact's delivery token into a
   sink, and delete the account (see
   [Deleting your account](ACCOUNT-DELETION.md)). While the account is
   suspended, the server accepts only the requests that clause 6.5.3 of the
   [Terms of Use](TERMS.md) lists: you can still see this data and delete the
   account, but you cannot turn off search by name or block a contact until
   the suspension ends. For a full copy, write to us as point 4 describes.
4. **In writing**, at the personal-data address on the
   [contact page](CONTACT.md), in Kazakh, Russian or English. The server holds
   no name, phone number or e-mail address for you, only the username, the
   account identifier, the dates and the keys listed in section 3. So we can
   act on a request about a specific account only if it is signed with that
   account's key. For the data in section 12, we act on a request made from
   the contact details you used to write to us. If we cannot confirm that data
   is yours, we tell you so and why (GDPR articles 11 and 12(2)).
5. We answer a request within the period the law sets, and in any case within
   10 working days of receiving it. Where the Kazakh law requires us to
   change, block or delete data within one working day, we do so. Requests are
   free. Where the GDPR applies and a request is manifestly unfounded or
   excessive, we may refuse it (GDPR article 12(5)). A refusal always states
   its reasons and how to challenge it.

> [!IMPORTANT]
> **To be filled in before release.** The name and website of the authorised
> body for personal-data protection of the Republic of Kazakhstan; and how a
> user signs a request about their account with the account's key, in the app
> or with a separate tool. Until that exists, point 4 and clause 15.3 of the
> [Terms of Use](TERMS.md) must not say that a request can be made or
> confirmed from the app.

## 10. Age

1. LUME is for people aged 18 and over, in every country. You may not create
   or use an account if you are under 18.
2. LUME collects no data that would show a user's age, so it cannot check it.
   The app asks you to confirm that you are at least 18 before it creates an
   account.
3. If we learn that an account belongs to someone under 18, we suspend it and
   tell the account in the app. We delete it only as clause 6.6.2 of the
   [Terms of Use](TERMS.md) describes for a suspended account: once an appeal
   has been rejected or, if no appeal made in time is pending, once 61 days
   have passed since the day the notice of the suspension was issued. The
   exception in that clause for a serious and repeated breach never applies to
   such an account.

## 11. The website

The LUME website sets no cookies, stores nothing on your device and uses no
analytics. See [the website page](WEBSITE.md).

## 12. Data we receive outside the server

1. When people write to us, at the addresses on the [contact page](CONTACT.md)
   or by post to our registered office, when LUME Inc. opens a report or takes
   a measure on an account, and when authorities send us requests, we receive
   or record personal data that the server does not hold. The table lists it.
   When you write to us, we receive only what you choose to send, and we use
   it only for the purposes given.

| Data | Why | Ground under the Kazakh law | Ground under the GDPR | How long |
|---|---|---|---|---|
| **Correspondence**: what you send to us, at an address on the contact page or by post to our registered office, the contact details you use, such as your name, postal address or e-mail address, your username if you give it, and our answers | to answer you and to keep a record of what was asked and answered | your consent, which you give by writing to us with these details; where a law requires us to receive and answer the message, also the cases in article 9 | legitimate interest in answering you and keeping a record (article 6(1)(f)); where EU or Member State law requires us to answer, legal obligation (article 6(1)(c)) | until the matter is closed, and then until the limitation period ends (point 4) |
| **Claims**, including the written claim to send before going to court, and complaints from rights holders: who makes the claim, how to reach them, the account concerned, the claim and the evidence sent with it | to examine and answer the claim, settle the dispute, and establish, exercise or defend legal claims | your consent, which you give by sending the claim; where a law requires us to answer it, also the cases in article 9 | performance of the contract (article 6(1)(b)) where the claim concerns the [Terms of Use](TERMS.md); otherwise legitimate interest in establishing, exercising or defending legal claims (article 6(1)(f)); legal obligation (article 6(1)(c)) where EU or Member State law requires an answer | until the dispute is settled, and then until the limitation period ends |
| **Notices of unlawful content and appeals against measures**: the sender's name and contact details, the username concerned, what the notice or appeal says, and our decision and its reasons | to examine the notice or appeal, to take, keep or reverse a measure under section 6 of the [Terms of Use](TERMS.md), and to answer with reasons | your consent, which you give by sending the notice or appeal; where a law requires us to receive and answer it, also the cases in article 9 | legal obligation (article 6(1)(c)) where EU law, such as the Digital Services Act, requires us to handle it; otherwise legitimate interest in enforcing the Terms and protecting users (article 6(1)(f)) | until the matter is closed, and then until the limitation period ends |
| **The record of measures**: for each measure we take on an account, the username and account identifier, the measure, the facts and the clause of the [Terms of Use](TERMS.md) on which it is based, and the decision on any appeal | to apply the measure, to tell the holder the facts and the clause on request ([Terms of Use](TERMS.md), clause 6.8), and to establish, exercise or defend legal claims | the consent of the account's holder ([Consent](CONSENT.md), item 3); where a law requires the measure, and after the account is deleted, the cases in article 9 | legitimate interest in enforcing the Terms and in establishing, exercising or defending legal claims (article 6(1)(f)); legal obligation (article 6(1)(c)) where EU law, such as the Digital Services Act, requires a statement of reasons | until the limitation period ends, counted from the day the measure ends or, for a warning or a deletion, the day it is taken |
| **Requests about personal data**: the request, the contact details used, the account it concerns, how we checked that the data is yours, and our answer | to answer the request and to show that we did | the duties of an operator under articles 24 and 25 of the Kazakh law | legal obligation (article 6(1)(c)) | until the request is answered, and then until the limitation period ends |
| **Opened reports**: the content of a report once authorised staff open it, that is, the reported messages as the reporter received them, which may contain personal data of the sender, the reporter and others, and the sender's identity keys | to act on abuse under section 6 of the [Terms of Use](TERMS.md) and the [Child Safety Standards](CHILD-SAFETY.md), and to meet legal duties | the reported user's consent ([Consent](CONSENT.md), item 3) and, after that user's account is deleted, the cases in article 9; the reporter's consent, which the reporter gives by sending the report; for other people named in the reported messages, the cases in article 9, including the protection of the rights of others where their consent cannot be obtained; for legal duties, the cases in article 9 | legitimate interest in protecting users and enforcing the Terms (article 6(1)(f)); legal obligation (article 6(1)(c)) where EU or Member State law requires action | until the decision on the report and any appeal against it are final, unless it is preserved as evidence |
| **Preserved evidence**: a copy of the account data listed in section 3 and of the reports about the account, kept where we delete an account for, or report, child sexual exploitation, where we report a threat to life, or where the law requires it or a competent authority lawfully asks us to preserve it | to give it to the competent authorities ([Law Enforcement Policy](LAW-ENFORCEMENT.md), [Child Safety Standards](CHILD-SAFETY.md)) | the cases in article 9 | legal obligation under EU or Member State law (article 6(1)(c)); otherwise legitimate interest in complying with the law of the Republic of Kazakhstan that applies to us (article 6(1)(f)); for a threat to life, vital interests (article 6(1)(d)) | for as long as the law requires or the authority lawfully asks; then we delete it |
| **The record of authority requests**: each request from a public authority, the authority and the officials who made it, the account it concerns, our answer and what we disclosed | to show that we answered lawfully, to defend our answer if it is challenged, and to count requests for the yearly numbers in the [Law Enforcement Policy](LAW-ENFORCEMENT.md), which contain no personal data | the cases in article 9 | legal obligation (article 6(1)(c)) where EU or Member State law requires the record; otherwise legitimate interest in showing that we acted lawfully (article 6(1)(f)) | until the limitation period for claims about the request ends, unless the law sets a longer period |
| **Vulnerability reports**: what a researcher sends through GitHub private vulnerability reporting ([SECURITY.md](../SECURITY.md)), with their GitHub username and anything else they choose to add | to investigate and fix the vulnerability, and to credit the researcher if they ask to be credited. If the vulnerability is in a third-party library, we tell the researcher first and then give the library's maintainers only its technical details, without anything that identifies the researcher | your consent, which you give by sending the report | legitimate interest in keeping LUME secure (article 6(1)(f)) | until the vulnerability is fixed and published or, if we find no vulnerability, until we close the report; a publication names the researcher only if they ask to be credited |

2. **Other people in these records.** A claim, notice, appeal, report or
   request may concern someone else, usually by username. We use that
   person's data only to deal with the matter. Under the Kazakh law, our
   ground for that person's data is the cases in article 9, including the
   protection of the rights of others where that person's consent cannot be
   obtained; under the GDPR, it is the ground the table gives for the record
   concerned. The source of that data is the person who wrote to us, or the
   reporter. When we take a measure on an account, we tell its holder as
   section 6 of the [Terms of Use](TERMS.md) describes.
3. **Where it is kept and who sees it.** We will keep the data in this section
   in the Republic of Kazakhstan, as article 12(2) of the Kazakh law requires,
   and only the staff who handle the matter can access it. This includes
   vulnerability reports: a researcher sends them to GitHub, which also holds
   them outside Kazakhstan under its own terms (section 7, item 4), and we
   keep a copy of each with the rest of this data. We disclose the data in
   this section only as section 7 describes, and to a court or competent
   authority where a dispute or the law requires it.
4. **How long.** Where the table says "until the limitation period ends", it
   means the limitation period that the law sets for claims about the matter.
   Where the law requires a longer period, that period applies. We then delete
   or destroy the data.

> [!IMPORTANT]
> **To be filled in before release.** The systems that hold the data in this
> section, such as the mail service and the storage for opened reports,
> preserved evidence, the record of measures and copies of vulnerability
> reports, and their location in the Republic of Kazakhstan; where the private
> key that opens reports is held, and where staff open reports (if anyone
> outside the Republic of Kazakhstan opens them, section 7 must list that
> transfer); fixed retention periods for each row, if LUME Inc. sets them; and
> a lawyer's confirmation of the Kazakh grounds in the table and in point 2,
> including the ground for other people named in reported messages and in the
> other records in this section, of the ground for keeping what section 9.2
> lists after an account is deleted, of the Kazakh ground for using in memory
> the addresses of people who connect to the server without an account
> (section 4), and of the condition under GDPR articles 9(2) and 10 for opened
> reports and preserved evidence that contain special categories of personal
> data or data about criminal offences.

## 13. Changes

1. We change this policy when the law, LUME's features or protocol, or our
   security measures change, or to make it clearer.
2. We announce material changes by a notice in the app, which links to the
   new text on our website, at least 15 calendar days before they take effect.
   If a change needs new consent, the app asks you to accept the new version
   and the server records your acceptance (section 3); until you accept it,
   we keep processing your data on the version you accepted. Changes required
   by law, or needed urgently for security, may take effect sooner, as the
   reason requires. If you do not accept a change, you can delete your account
   at any time, free of charge.
3. Changes that only correct or clarify the text, without changing what we
   process or why, take effect when published.
4. Every version of this document is kept in the public history of our
   repository.

## 14. Language

This policy is published in English. Before you accept it, the app shows, on
the screen where you accept, a short summary of the main terms of the
[Terms of Use](TERMS.md), this policy and the [Consent](CONSENT.md) in Kazakh
and Russian, for information. The English text governs.
