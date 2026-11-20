<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# LUME Law Enforcement Policy

**Status: draft.** Takes effect with the first public release.

This policy explains to public authorities and to users what data LUME Inc.
(ТОО «LUME Inc.», BIN 260740032421) holds about LUME accounts, what it cannot
provide, and on what conditions it answers a request for data.

It covers only the LUME relay that LUME Inc. runs. The LUME code is open source,
and anyone may run a relay of their own. LUME Inc. holds no data about another
operator's relay or its users and cannot answer for them.

This policy describes how LUME Inc. handles requests. It gives no authority or
other person a right to data beyond what the law gives, and it does not waive
any objection or remedy that the law gives LUME Inc. or its users. We may update
it; the current version is the one published on our website, and its history is
public in our repository.

## 1. What exists

1. About an account, the server holds only the data listed in section 3 of the
   [Privacy Policy](PRIVACY.md), for the periods given there. For one account,
   that is:
   - the username and the random account identifier that the server assigned
     to the account;
   - the account's public keys and the signatures on them, its generation
     number (how many times the account was recovered on a new device) and its
     discoverability setting;
   - the **day** the account was created and the **day** it last connected,
     without a time;
   - the number of the version of the Terms of Use, the Privacy Policy and the
     Consent that the user accepted, and the **day** on which they accepted it;
   - any measure on the account (a restriction or a suspension) and the day on
     which it ends;
   - notices from LUME Inc. that have not yet reached the account, each with
     its kind and day, at most 20 and for at most 30 days;
   - the hashes of the delivery tokens the account issued, whether each is
     active, blocked or left over from a previous device, and the days on which
     each was created and last used, but not to whom it was issued;
   - the hashes of its live invite codes, at most five, and when each expires;
     each expires 24 hours after it is created;
   - records of which of the account's one-time keys were handed out, and on
     which day, over the last 15 days, with nothing about who asked for them;
   - encrypted messages awaiting delivery to the account, each kept for at most
     30 days, with the time it arrived and the hash of the delivery token or
     invite it came with; we cannot decrypt them;
   - for a message awaiting delivery that a stranger sent without an invite,
     a hash of the sender's network (the /48 IPv6 or /24 IPv4 block), keyed
     with a key that changes every day; it is not the address, the address
     cannot be read from it, and it is deleted with the message;
   - encrypted attachments awaiting download by the account, with their size,
     the downloads left and the expiry time, each kept for at most 30 days; we
     cannot decrypt them;
   - reports by other users about messages from the account, which LUME Inc.
     can open, kept for the period section 3 of the
     [Privacy Policy](PRIVACY.md) gives;
   - after an account is deleted, a hash of its username while the name is
     held or barred, and the day until which it is.
2. A request can reach only data that exists when we receive it. Data is
   deleted automatically at the end of the periods in the Privacy Policy, and
   deleted records are overwritten, so they cannot be recovered.
3. A report holds the reported messages as the reporter received them and the
   sender's identity keys. It is evidence of what the reporter says, not proof
   that the messages were sent. The server stores reports without linking them
   to an account, so we find the reports about an account only by opening the
   reports we hold.
4. Outside the server, LUME Inc. holds only the data that section 12 of the
   [Privacy Policy](PRIVACY.md) lists, such as: what people send to the
   addresses on the [contact page](CONTACT.md) or by post to our registered
   office, with the contact details they chose to give; the reports we have
   opened; evidence preserved under clause 4.6 or the
   [Child Safety Standards](CHILD-SAFETY.md); the record of measures taken on
   accounts, with the facts and the clause of the Terms of Use on which each
   is based; copies of vulnerability reports ([SECURITY.md](../SECURITY.md));
   and the record in clause 4.10.

## 2. What does not exist

We do not have and cannot provide:

- the content of messages or attachments, other than messages a recipient has
  reported to us; we do not hold, and have never held, the keys to decrypt
  them;
- private keys, recovery phrases or passphrases; they never leave the user's
  device;
- contact lists, or who an account talks to;
- the sender of any stored message or attachment;
- who sent a report;
- phone numbers, e-mail addresses, names, dates of birth, location or payment
  details; we do not collect them, and we hold contact details only where a
  person has sent them to us in correspondence (clause 1.4);
- IP addresses or logs of them; addresses are used in memory and never
  recorded;
- group names, members or roles, display names, profile photos, or typing and
  read state; the server holds none of them;
- service logs about an account; the logs hold events, counts, durations and
  error codes, and no usernames, account identifiers, tokens, addresses or
  message content;
- records of visits to the LUME website; we receive none.

**There is no backdoor.** The source code and the cryptography are published,
so anyone can check that they contain none. We will not build one voluntarily.
We would contest any demand to build one by every lawful means, and we would
tell users about it where the law allows.

## 3. What a request must contain

1. Except in an emergency under clause 4.9, we answer a request for data only
   if it is lawful and it:
   - comes from an authority of the Republic of Kazakhstan that is competent to
     make it under the law of the Republic of Kazakhstan, in the form and by the
     procedure that law sets;
   - reaches us through a proper channel of international legal assistance,
     such as a request under a treaty to which the Republic of Kazakhstan is a
     party; or
   - comes directly from a foreign authority and clause 3.3 allows us to answer
     it directly.
2. The request must be in writing, on paper or as an electronic document,
   signed by an authorised official. It must state its legal basis and contain
   what the law requires for that kind of request, including, where the law
   requires it, the sanction or consent of a court or prosecutor. So that we
   can answer quickly and disclose no more than is needed, we ask that it also
   state:
   - the authority, and the name and position of the official;
   - the case or proceeding number, where there is one;
   - the account, identified by its username, its account identifier or its
     identity key;
   - the specific data from section 1 that is sought, and the period it
     concerns;
   - the deadline for the answer.
3. A foreign authority must use international legal assistance. We answer a
   request sent to us directly by a foreign authority only to the extent that
   a law binding on LUME Inc. requires us to answer it directly and the law of
   the Republic of Kazakhstan does not forbid it. Otherwise we refer the
   authority to international legal assistance. We transfer data to an
   authority or body in another country only through international legal
   assistance; when we report child sexual exploitation or a threat to life to
   a foreign competent authority or a recognised body, under clause 4.9 or as
   the [Child Safety Standards](CHILD-SAFETY.md) describe; or where another
   law binding on LUME Inc. requires it. In each case we transfer only the
   data that the case requires, and only where the law of the Republic of
   Kazakhstan on the cross-border transfer of personal data permits it.
4. Private persons, including parties to civil cases and their lawyers, receive
   data about another person's account only under a court order binding on
   LUME Inc. Users can see the data the server holds about their own account in
   the app, as the [Privacy Policy](PRIVACY.md) describes.
5. We do not accept requests by telephone, in person without a written
   request, through social media, or in public issues in our repository.

> [!IMPORTANT]
> **To be filled in before release.** A lawyer confirms clause 3.3 against the
> rules of the European Union on orders for electronic evidence and on orders
> to act against illegal content, and whether LUME Inc. must appoint a
> representative to receive such orders, if LUME is offered in the European
> Union.

## 4. How we respond

1. We check every request for its authenticity, the competence of the
   authority, its form, its legal basis and its scope. We may confirm that a
   request is genuine through the authority's official channels before we act
   on it.
2. We may refuse a request, ask for it to be corrected or narrowed, or answer
   it only in part, if it is not lawful, does not meet clause 3.1 or the form
   and legal basis required by clause 3.2, is broader than its legal basis
   allows, is unclear, or seeks data about people it does not concern. We may
   challenge a request by the means the law provides, including a complaint to
   a prosecutor or a court.
3. We disclose only data that exists and that the request lawfully covers, and
   no more than the law requires.
4. We disclose no message or attachment content, except a reported message we
   hold. Messages and attachments awaiting delivery are encrypted under keys we
   do not have. We hand them over only where a court order or another act that
   the law makes binding on us specifically requires it, and then only in the
   encrypted form in which we hold them.
5. We consider a request within the period the law sets for that kind of
   request. We answer within the period the law sets, or by the deadline in
   the request where that deadline is lawful.
6. On a written request to preserve data from a competent authority, we may
   preserve data that exists about a specified account until a request under
   section 3 arrives, but for no longer than the law permits. If none arrives,
   we delete the preserved data.
7. We carry out a lawful order of a court or a competent authority to restrict,
   suspend or delete an account, or to bar a username, subject to our right to
   challenge it under clause 4.2. The server does not know who sends a
   message, so a restriction or a suspension cannot itself stop the account
   from sending one (clause 6.5 of the [Terms of Use](TERMS.md)).
8. We notify the user in the app before we disclose data about their account,
   so that they can seek legal help, unless the law, a court or the authority
   acting within its powers forbids it, or the disclosure is made in an
   emergency under clause 4.9. The LUME app shows the notice and links to its
   full text on our website. If the account is not connected, the notice
   waits on the server until the account next connects, for at most 30 days,
   so it may reach the user only after the disclosure. We hold no contact
   details for users other than those a person has sent us (clause 1.4), so
   the app is the way we notify a user.
9. In an emergency involving an imminent threat to a person's life, we may
   disclose to a competent authority, of our own motion or on its request, the
   data in section 1 that exists and that is needed to prevent the threat. We
   disclose nothing else in an emergency, and we may ask for a request under
   section 3 afterwards. If a report we open shows a real threat to a person's
   life, we tell the competent law enforcement authority at once, as the law
   requires.
10. We keep a record of each request, our answer and what we disclosed, for the
    period the [Privacy Policy](PRIVACY.md) gives.

## 5. Transparency

At least once a year, to the extent the law allows, we publish how many
requests we received, from which countries, how many we answered and what data
we provided.

## 6. Contact

Send requests to the address for public authorities on the
[contact page](CONTACT.md).

> [!IMPORTANT]
> **To be filled in before release.** The address for public authorities (see
> the [contact page](CONTACT.md)).
