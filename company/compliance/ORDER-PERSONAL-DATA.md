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
   - action under the [Procedure for a personal-data security breach](BREACH-RESPONSE.md).
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
article 30.

| No. | Data | Purpose | Basis (Kazakhstan / GDPR) | Retention | Where stored |
|---|---|---|---|---|---|
| 1 | Username | finding and checking a contact | consent / contract | until the account is deleted, or 365 days without a connection | relay server |
| 2 | Random account identifier, assigned by the server | addressing messages and attachments | consent / contract | as long as the account | relay server |
| 3 | Public keys of the account (identity key, device key, prekeys) | starting an encrypted conversation, checking requests | consent / contract | the same; one-time keys until handed out | relay server |
| 4 | Account generation number | cutting off the old device after a recovery | consent / contract | the same | relay server |
| 5 | Discoverability setting | control over search by username | consent / contract | the same | relay server |
| 6 | Day of creation and day of the last connection | deleting inactive accounts, limits for new accounts | consent / legitimate interest | the same | relay server |
| 7 | Records of one-time keys handed out | replenishing the stock of keys | consent / contract | 15 days | relay server |
| 8 | Hashes of delivery tokens, with the days of creation and last use | receiving messages from contacts, blocking | consent / contract | until revoked or the account is deleted; inherited tokens 45 days without use | relay server |
| 9 | Hashes of invite codes | contact while search by username is off | consent / contract | 24 hours | relay server |
| 10 | Encrypted messages and attachments awaiting delivery; for a message from a stranger, a hash of the sender's network | delivery; protection against spam | consent / contract and legitimate interest | messages until acknowledged, attachments until their downloads are used; at most 30 days | relay server |
| 11 | Reports (sealed messages and the reported sender's keys) | responding to abuse | consent / legitimate interest, legal obligation | 90 days, or longer where the law requires | relay server |
| 12 | Hashes of held and barred usernames | protection against username takeover | consent / legitimate interest | 31 days; barred names for as long as the bar lasts | relay server |
| 13 | IP address | delivery, rate limiting | consent / legitimate interest | not stored; held in memory only | relay server |

**Data subjects:** LUME users. **Recipients:** the hosting provider (under a
processing agreement); public authorities, in the cases set by law. **Place of
storage:** the relay server in a data centre in the Republic of Kazakhstan
(paragraph 2 of article 12 of the Law). **Cross-border transfer:** none.
**Security measures:** section 8 of the Privacy Policy.
