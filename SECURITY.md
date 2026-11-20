<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Security

LUME is an encrypted messenger, so a vulnerability report is the most useful
thing you can send us. This policy is issued by LUME Inc. (ТОО «LUME Inc.»),
Republic of Kazakhstan, BIN 260740032421. It says how to report a
vulnerability, what you may test and on what terms, and what LUME Inc. promises
in return. "We" means LUME Inc.

## Reporting a vulnerability

1. Use GitHub private vulnerability reporting in this repository: *Security →
   Report a vulnerability*. Please do not open a public issue about a
   vulnerability, and do not disclose it before it is fixed or before the date
   we agree with you. This channel is for vulnerabilities only: send claims,
   requests about personal data and anything else as the
   [contact page](legal/CONTACT.md) explains.
2. A useful report says what breaks, how to reproduce it and what an attacker
   gains. A proof of concept is welcome but not required.
3. We first respond within 72 hours. We tell you whether the vulnerability is
   confirmed and when to expect a fix, and we agree a publication date with
   you, as a rule no later than 90 days after the report.
4. If the vulnerability is being exploited, or its details become public, we
   may publish a fix or a warning earlier to protect users. Where we can, we
   tell you first.
5. If the vulnerability is in a third-party library that LUME uses, such as
   libsodium or liboqs, we may share the technical details of your report
   with the library's maintainers so that they can fix it. We tell you before
   we do, and we leave out your name, your GitHub username and anything else
   that identifies you.
6. By sending a report, you allow LUME Inc. to use what it contains to
   investigate, fix and publish the vulnerability. The publication names you
   only if you ask to be credited; if you want that, say so in the report.
7. GitHub, Inc. (USA) receives and holds what you send through private
   vulnerability reporting, under its own terms. LUME Inc. keeps a copy of
   each report in the Republic of Kazakhstan and uses it only as this section
   describes. It keeps the copy until the vulnerability is fixed and
   published or, if no vulnerability is found, until the report is closed.
   Apart from items 5 and 6, it discloses a report only to a court or a
   competent authority, where the law requires it. Its ground under the law
   of the Republic of Kazakhstan is the consent you give by sending the
   report; under the GDPR, it is its legitimate interest in keeping LUME
   secure (article 6(1)(f)). Section 12 of the
   [Privacy Policy](legal/PRIVACY.md) describes this processing.

## Rewards

1. There is no bug bounty. LUME Inc. has no obligation to pay a reward, a fee
   or any other compensation for a report, whatever its quality or impact.
2. A report does not create a contract for services, an employment
   relationship or any right to payment.
3. Demanding payment for the details, or for not publishing them, is outside
   this policy and may be a crime. The promises in the next section do not
   apply to it.

## Good-faith research

### The rules

The promises below apply only to research done in good faith that follows
every one of these rules:

1. **Report privately first.** Report through the channel above before you
   tell anyone else, and do not disclose the vulnerability to anyone before the
   fix or the agreed date.
2. **Stay in scope.** Test only what the
   [scope section](#what-is-in-scope-now) lists, and only on your own accounts,
   devices and builds, on the accounts and devices of people who have agreed in
   advance, and on a relay that you run yourself from this repository's code.
3. **Go no further than the proof.** Use the vulnerability only as far as you
   need to show that it exists. Do not read, copy, keep, change or delete
   other people's data. If you reach it by accident, stop, do not use or share
   it, delete it, and tell us in your report.
4. **Do not disrupt.** No denial of service or load testing, no spam or
   flooding, no physical attacks, and no phishing or other social engineering
   against users, LUME Inc. or the people who work for it.
5. **Leave other people's systems alone.** Do not test systems that LUME Inc.
   does not own, such as GitHub, which hosts this repository and the live
   website, app stores, hosting providers, or the projects whose libraries LUME
   uses. Report problems in them to their owners under their own rules.
6. **Leave nothing behind.** Do not install backdoors, keep access or spread
   malware. A proof of concept must do no more than show the vulnerability.
7. **Make no demands.** Do not demand money or anything else in return for
   the details or for keeping them private.

If you are unsure whether something is allowed, ask through the reporting
channel before you do it.

### What LUME Inc. promises

For research that follows the rules:

1. LUME Inc. treats the research as authorised by it, as the owner of the code
   and systems concerned, including for the purposes of laws on unauthorised
   access to computer information, such as the Criminal Code of the Republic of
   Kazakhstan.
2. LUME Inc. will not initiate or support any civil claim, criminal complaint
   or report to law enforcement against you over that research.
3. The research is not a breach of the [Terms of Use](legal/TERMS.md).
4. If a public authority or anyone else asks, LUME Inc. will confirm that your
   research was authorised and followed this policy, to the extent the law
   allows.
5. If you break a rule by accident, and you stop at once and tell us in your
   report, LUME Inc. takes your good faith into account.

### What the promise cannot do

1. The promise is made by LUME Inc. alone. It cannot bind prosecutors,
   courts, other public authorities, other users or any other person, and it
   is not immunity from prosecution. LUME Inc. cannot stop proceedings that the
   law requires an authority to bring.
2. LUME Inc. can authorise access only to what it owns. It cannot authorise
   access to other people's accounts, devices or data, or to systems that
   belong to others.
3. The promise does not cover research that breaks the rules, is done in bad
   faith or harms users. In that case LUME Inc. keeps every right and remedy
   that the law gives it.
4. Nothing in this policy releases anyone from liability to other people for
   harm they suffer, or overrides what the law requires of LUME Inc. or of you.
5. LUME Inc. may change this policy. The good-faith research rules, with the
   scope section that rule 2 refers to, are part of the
   [Terms of Use](legal/TERMS.md) (clause 15.6), so once the Terms of Use are
   in effect, a change to them is published as a new version of the Terms of
   Use and takes effect as section 14 of the Terms of Use describes. A change
   does not withdraw the promise from research done while an earlier version
   was in force.

## What is in scope now

**LUME is under development. Nothing is released and no relay is running.**
The code today is the core library in `core/`, the website generator in
`site/`, and the build, test and check tools in `tools/`. The core library has
the cryptographic primitives, the identity and recovery phrase, safety numbers,
the wire format, the handshake, the Double Ratchet, the encoding of message
content, sealed sender and padding, directory key lists, introduction cards,
and the vault's key schedule and file formats. The relay server and the apps
are not written yet.

Reports about that code are welcome now. Above all, we want anything that
breaks a claim in [`docs/CRYPTO.md`](docs/CRYPTO.md) or
[`docs/PROTOCOL.md`](docs/PROTOCOL.md): key agreement, the Double Ratchet, the
vault, the message format, or a way for the relay to learn something it should
not. Flaws in the specifications themselves are in scope too.

In scope:

1. the code in `core/`, `site/` and `tools/`, including its tests and build
   files;
2. the specifications in `docs/`;
3. the website, only as its source in `site/` and the files that source
   produces, examined in your own browser or in a local build
   (`python site/build.py --serve`);
4. the way LUME uses third-party libraries, such as libsodium and liboqs.

Out of scope:

1. anything else in this repository, unless we agree otherwise in writing
   first;
2. the third-party libraries themselves, and the systems listed in rule 5;
3. active testing of the live website at
   [lumeincc.github.io/lume](https://lumeincc.github.io/lume/), which GitHub
   hosts (rule 5). You may visit it and read its pages and files like any
   other visitor;
4. any server that claims to be a LUME relay. LUME Inc. runs none yet, so
   there is no LUME Inc. service to test.

When the relay and the apps exist, this section will name them.

## What LUME holds to

- The cryptography comes from libsodium and liboqs. LUME combines vetted
  primitives and invents none. If it has invented one by accident, that is
  exactly the report we want.
- It fails closed: a cryptographic error never leads to sending or showing
  unencrypted data.
- The relay is designed to store only what delivery, protection against abuse
  and the legal record need ([section 7 of the protocol
  specification](docs/PROTOCOL.md#7-what-the-relay-stores)): whom a sealed
  envelope is for, never who sent it.
- What LUME does not protect against is written down in [section 1 of the
  cryptography specification](docs/CRYPTO.md#1-goals-and-non-goals), not left
  for readers to discover.
