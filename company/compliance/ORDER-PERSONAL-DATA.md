<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Order on personal data (template)

**LUME Inc. (ТОО «LUME Inc.»)**, BIN 260740032421
Temirtau

**ORDER No. ____** dated ____ __________ 20__

**On approving the policy and the list of personal data, and on appointing the
person responsible for organising the processing of personal data**

Under sub-paragraphs 1), 1-1) and 10) of paragraph 2 of article 25 of Law of the
Republic of Kazakhstan No. 94-V of 21 May 2013 "On Personal Data and Their
Protection", **I ORDER:**

1. To approve the LUME Privacy Policy as published in the repository
   `github.com/lumeincc/lume`, file `legal/PRIVACY.md` (commit ________), as
   the document that sets out the policy of LUME Inc. on the collection,
   processing and protection of personal data.
2. To approve the list of personal data that is necessary and sufficient for
   the tasks performed (appendix 1 to this order).
3. To approve the text of the consent to the collection and processing of
   personal data: file `legal/CONSENT.md` (the same commit).
4. To appoint ______________________ (position, surname, initials) as the
   person responsible for organising the processing of personal data, with the
   following duties:
   - internal control over compliance by LUME Inc. and its employees with
     the law on personal data;
   - informing employees of the law on personal data and of the internal
     documents on the subject;
   - control over the receipt and handling of requests from data subjects;
   - action under the
     [Procedure for a personal-data security breach](BREACH-RESPONSE.md).
5. To approve the Procedure for a personal-data security breach: file
   `company/compliance/BREACH-RESPONSE.md` (the same commit).
6. To grant access to the server that processes personal data only to
   employees who need it for their duties, according to a list approved by the
   director.
7. I reserve control over the execution of this order.

Director ______________________ / ____________ /

Acknowledged: ______________________ ____ __________ 20__

---

## Appendix 1. List of personal data and processing operations

This appendix also serves as the record of processing activities under GDPR
article 30. It covers the same data as sections 3, 4 and 6 of the Privacy
Policy and its section 12 on data received outside the server, with the same
purposes, grounds and periods. When either text changes, the other changes in
the same commit.

"Consent" means the consent to the collection and processing of personal data
that the user gives by pressing I accept in the app before the account is
created or, with software other than the official apps, by registering the
account (`legal/CONSENT.md`). "Article 9" means the cases of processing without
consent in article 9 of the Law. The GDPR grounds are those of article 6(1):
(b) contract, (c) legal obligation, (d) vital interests and (f) legitimate
interest. Ground (c) applies only where EU or Member State law imposes the
obligation; where only the law of the Republic of Kazakhstan does, the ground
is (f).

### A. Data held on the relay server

| No. | Data | Purpose | Basis (Kazakhstan / GDPR) | Retention | Where stored |
|---|---|---|---|---|---|
| 1 | Username | finding a contact and checking that a name belongs to its keys | consent / (b) | until the account is deleted, or 365 days without a connection | relay server |
| 2 | Random account identifier, assigned by the server | addressing messages, attachments, notices and requests for keys | consent / (b) | as long as the account | relay server |
| 3 | Public keys of the account and their signatures: identity keys and the signature that binds them, device key, signed and one-time prekeys, each with its number and time of creation | starting an encrypted conversation; checking that requests come from the account's device | consent / (b) | as long as the account; a one-time key until handed out or withdrawn; a signed key until replaced; a previous device's keys until a recovery on a new device | relay server |
| 4 | Account generation number | disconnecting the old device after a recovery | consent / (b) | as long as the account | relay server |
| 5 | Discoverability setting | control over search by username | consent / (b) | as long as the account | relay server |
| 6 | Day of creation and day of the last connection, without a time | deleting inactive accounts; the stricter limits for accounts younger than 7 days | consent / (b) and (f) | as long as the account | relay server |
| 7 | Record of acceptance: the number of the version of the Terms of Use, the Privacy Policy and the Consent the user accepted, and the day of acceptance | proof of consent (article 25(2) sub-paragraph 5) of the Law) and of the conclusion of the contract; asking the user to accept a new version | consent and article 25(2) sub-paragraph 5) / (b) and (f) | as long as the account; replaced when the user accepts a later version | relay server |
| 8 | Measure on the account: whether it is restricted or suspended, and the day the measure ends | applying a measure that LUME Inc. decided under section 6 of the Terms of Use | consent / (f) | while the measure lasts, and at most as long as the account | relay server |
| 9 | Notices waiting for the account: the kind of notice and the day it was issued | telling the user of a change to the Terms of Use, the Privacy Policy or the Consent, a notice required before a lawful disclosure, a warning to the account, a measure on the account or its end, a security incident that affects the account, a transfer of the service to a successor or the end of the service | consent; article 9 where a law requires the notice / (b); (c) where EU or Member State law requires the notice | until delivered to the account; at most 20 per account and 30 days | relay server |
| 10 | Records of one-time keys handed out: which key, a sequence number and the day | replenishing the stock of keys | consent / (b) | 15 days | relay server |
| 11 | Hashes of delivery tokens, each with its state (live, blocked or inherited from a previous device) and the days of creation and last use | receiving messages from contacts; discarding a blocked contact's messages | consent / (b) | a live token until replaced or the account is deleted; a blocked token until the account is deleted; an inherited token 45 days without use | relay server |
| 12 | Hashes of invite codes, with their expiry time | contact while search by username is off | consent / (b) | 24 hours, or until revoked or a recovery on a new device | relay server |
| 13 | Encrypted messages awaiting delivery, each with the recipient, the generation, the time of arrival to the second and the lane: the delivery token hash, the invite hash, or, for a message from a stranger without an invite, a hash of the sender's network keyed with a key that changes daily | delivery; protection against spam | consent / (b) and (f) | until acknowledged; at most 30 days; earlier on a recovery, when a full queue or a shortage of disk space evicts it | relay server |
| 14 | Encrypted attachments, each with its identifier, size, recipient, a hash of its upload key, the downloads left and its expiry time | delivery | consent / (b) | until the downloads are used; at most 30 days; earlier on a shortage of disk space | relay server |
| 15 | Reports: the reported messages as the reporter received them and the reported sender's identity keys, sealed to LUME Inc.'s report key, with the time of arrival to the second | acting on abuse; enforcing the Terms of Use; legal duties | consent; after the account is deleted, article 9 and article 8(2) of the Law; article 9 for legal duties / (f); (c) where EU or Member State law requires action | 90 days; a copy kept longer where the law requires it is row 23 | relay server |
| 16 | Hashes of held and barred usernames, with the reason and the day the hold or bar ends | protection against username takeover; enforcing a bar | consent; after the account is deleted, article 9 (a held name) or article 9 and article 8(2) of the Law (a barred name) / (f) | a held name 31 days; a barred name while the bar lasts; at most 100,000 names, oldest removed first | relay server |
| 17 | IP address and connection time | delivery; rate limits, proof of work and the stricter limits for new accounts | consent / (b) and (f) | not stored; held in memory only, in counters of fixed size | relay server memory |

Any data in rows 1 to 16 may also be processed to act on reports and enforce
the Terms of Use: consent / (f); to meet legal duties (answering lawful
requests, preserving data, reporting child sexual exploitation): consent and
article 9 / (c) where EU or Member State law imposes the duty, otherwise (f);
and to prevent a threat to someone's life or of serious harm to their health:
article 9 / (d). A copy kept for these purposes is row 23.

Also processed, but not stored in the database: the username certificate,
which is signed when it is needed and cached until the end of that day (purpose
and basis as rows 1 to 4); and encrypted typing and presence messages, which
are passed on only while the recipient is connected and are otherwise dropped,
never stored (purpose and basis as row 13).

### B. Data received outside the server

| No. | Data | Purpose | Basis (Kazakhstan / GDPR) | Retention | Where stored |
|---|---|---|---|---|---|
| 18 | Correspondence sent to LUME Inc., at its contact addresses or by post to its registered office: what the sender sends, the contact details used, such as name, postal address or e-mail address, the username if given, and LUME Inc.'s answers | answering; keeping a record of what was asked and answered | consent given by writing; article 9 where a law requires an answer, and for other people named in it / (f); (c) where EU or Member State law requires an answer | until the matter is closed, then until the limitation period ends | Republic of Kazakhstan; system: see the box below |
| 19 | Claims, including the written claim before going to court, and complaints from rights holders: the claimant, how to reach them, the account concerned, the claim and its evidence | examining and answering the claim; settling the dispute; legal claims | consent given by sending the claim; article 9 where a law requires an answer, and for other people named in the claim / (b) where the claim concerns the Terms of Use, otherwise (f); (c) where EU or Member State law requires an answer | until the dispute is settled, then until the limitation period ends | Republic of Kazakhstan; system: see the box below |
| 20 | Notices of unlawful content and appeals against measures: the sender's name and contact details, the username concerned, the notice or appeal, and the decision and its reasons | examining the notice or appeal; taking, keeping or reversing a measure; answering with reasons | consent given by sending it; article 9 where a law requires an answer, and for other people named in it / (c) where EU law, such as the Digital Services Act, requires it, otherwise (f) | until the matter is closed, then until the limitation period ends | Republic of Kazakhstan; system: see the box below |
| 21 | Requests about personal data: the request, the contact details used, the account concerned, how the data was checked to be the requester's, and the answer | answering the request and showing that it was answered | articles 24 and 25 of the Law; article 9 for other people named in it / (c) | until the request is answered, then until the limitation period ends | Republic of Kazakhstan; system: see the box below |
| 22 | Contents of reports opened by LUME Inc.'s staff: the reported messages as the reporter received them and the sender's identity keys | deciding on a report and any appeal against the decision; legal duties | the reported user's consent, and article 9 after that user's account is deleted; the reporter's consent; article 9 for other people named in the reported messages and for legal duties / (f); (c) where EU or Member State law requires action | until the decision on the report and any appeal against it are final, unless kept under row 23 | Republic of Kazakhstan; system: see the box below |
| 23 | Preserved evidence: a copy of an account's data from rows 1 to 16 and of the reports about it, kept where LUME Inc. deletes an account for, or reports, child sexual exploitation, reports a threat to life, or where the law requires it or a competent authority lawfully asks to preserve it | handing evidence to competent authorities | article 9 / (c) where EU or Member State law requires it, otherwise (f); (d) for a threat to life | as long as the law requires or the competent authority lawfully asks, then deleted | Republic of Kazakhstan; system: see the box below |
| 24 | Record of each request from a public authority: the authority and the officials who made it, the account concerned, LUME Inc.'s answer and what it disclosed | proving lawful handling of requests; the yearly numbers, which contain no personal data | article 9 / (c) where EU or Member State law requires the record, otherwise (f) | until the limitation period for claims about the request ends, unless the law sets a longer period | Republic of Kazakhstan; system: see the box below |
| 25 | Vulnerability reports: the reporter's account name on GitHub and the content of the report | investigating and fixing vulnerabilities; crediting the reporter if they ask; the maintainers of an affected third-party library receive only the technical details, after the reporter is told, without anything that identifies the reporter | consent given by sending the report / (f) | until the vulnerability is fixed and published, and the credit, if asked for, is published; if no vulnerability is found, until the report is closed | the Republic of Kazakhstan, as rows 18 to 24; GitHub, Inc. (USA) also holds the report where the reporter files it (transfer item 4) |
| 26 | Record of measures: for each measure LUME Inc. takes on an account, the username and account identifier, the measure, the facts and the clause of the Terms of Use on which it is based, and the decision on any appeal | applying the measure; telling the holder the facts and the clause on request (clause 6.8 of the Terms of Use); legal claims | consent; article 9 where a law requires the measure, and after the account is deleted / (f); (c) where EU law, such as the Digital Services Act, requires a statement of reasons | until the limitation period ends, counted from the day the measure ends or, for a warning or a deletion, the day it is taken | Republic of Kazakhstan; system: see the box below |

> [!IMPORTANT]
> **To be filled in before release.** For rows 18 to 26: the systems that hold
> the data, which must be in the Republic of Kazakhstan under paragraph 2 of
> article 12 of the Law, as the Privacy Policy commits (a copy abroad is a
> cross-border transfer, which article 16 must allow and the list below must
> name); the e-mail service used for the contact addresses; any fixed
> retention periods; where the report private key is held; and where staff
> open reports. The Privacy Policy names no system, place or period that has
> not been chosen.

**Data subjects:** LUME users; people who write to LUME Inc.; people who report
vulnerabilities; other people named in reports, claims, notices, appeals and
requests; officials of public authorities who make requests. **Recipients:**
the hosting provider, under a processing agreement; other users, who receive a
user's username, public keys and certificate when they look the user up;
public authorities, in the cases set by law; the authorities and recognised
bodies that receive reports of child sexual exploitation or of a threat to
life; GitHub, Inc. (USA), which holds vulnerability reports (row 25); a
successor that takes on the Privacy Policy, after notice to users in the app.
**Place of storage:** section A, the relay server in a data centre in the
Republic of Kazakhstan (paragraph 2 of article 12 of the Law); section B, the
Republic of Kazakhstan, in the systems named in the box above, and GitHub,
Inc. (USA) also holds vulnerability reports (row 25).

**Cross-border transfer:** no routine transfer. Data is transferred abroad
only, under article 16 of the Law:

1. to foreign competent authorities through international legal assistance
   under a treaty of the Republic of Kazakhstan;
2. to a foreign competent authority or recognised body, when LUME Inc. reports
   child sexual exploitation or a threat to life, as the law requires or
   allows;
3. where any other law binding on LUME Inc. requires it; and
4. where a person chooses to send LUME Inc. something through GitHub private
   vulnerability reporting, which GitHub, Inc. (USA) holds under its own
   terms (row 25), on the consent the sender gives by sending it.

**Security measures:** section 8 of the Privacy Policy.
