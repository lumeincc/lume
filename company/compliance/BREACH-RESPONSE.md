<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Procedure for a personal-data security breach

An internal document of LUME Inc. (ТОО «LUME Inc.»). It is approved by the
order on personal data ([ORDER-PERSONAL-DATA.md](ORDER-PERSONAL-DATA.md)).

A **personal-data security breach** is a breach of the protection of personal
data that leads to their unlawful dissemination, alteration, destruction or
deletion, or to unauthorised access to them (sub-paragraph 15-2) of article 1
of Law of the Republic of Kazakhstan No. 94-V "On Personal Data and Their
Protection").

## 1. Who acts

The person responsible for organising the processing of personal data, or the
director when that person is absent. Any employee who notices signs of a breach
tells the responsible person at once.

## 2. Deadlines

| Step | Deadline |
|---|---|
| Stop the breach: close access, change keys and passwords, keep logs and copies of the affected systems for the investigation | immediately |
| Notify the authorised body for personal-data protection of the Republic of Kazakhstan, giving the responsible person's contact details, a description of the breach, the data affected and the measures taken (sub-paragraph 8) of paragraph 2 of article 25 of the Law; the notification rules are set by order of the authorised body No. 232/НҚ of 30 April 2026) | no later than one working day after discovery |
| Notify the EU supervisory authority, through the EU representative, if people covered by GDPR are affected and there is a risk to their rights (GDPR article 33) | no later than 72 hours after discovery |
| Tell users in the app and on the website what happened, which data are affected and what to do, if the breach may affect their rights (GDPR article 34) | without undue delay |
| Enter the breach in the breach log: date, nature, data, number of accounts affected, measures, notifications | straight after the notifications |
| Remove the cause, check that it is removed, and write down the lessons | when the investigation ends |

If a rule of the authorised body sets a different deadline or different content
for the notification, the authorised body's rule applies.

## 3. What to consider in the assessment

- What may have leaked: section 3 of the [Privacy Policy](../../legal/PRIVACY.md)
  lists everything the server holds. Apart from reports, the content of
  messages and attachments is encrypted with keys LUME Inc. does not have, so a
  leak from the server does not reveal it, but it does reveal the metadata
  listed there.
- Whether stored reports are affected. A report holds the messages a user
  reported and the reported sender's keys, sealed to LUME Inc.'s report key.
  Reported messages can be read with that key, so stored reports are personal
  data in a breach, and their content is exposed if they leak together with
  the report key.
- Whether the directory key, which signs usernames, or the report key is
  affected: if either is compromised, it must be replaced at once and users
  must be told through the app.
- Whether a crime must be reported to law enforcement.

## 4. Breach log

The responsible person keeps the log. It is kept outside the relay server,
holds no more personal data of users than necessary, and is kept for at least
five years.
