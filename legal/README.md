<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# legal/

The user-facing documents of LUME Inc. (ТОО «LUME Inc.», Republic of
Kazakhstan, BIN 260740032421, Temirtau, Karaganda Region) for LUME, its
apps, its relay and its website.

The documents are published in English. On the screen where the user accepts
them, the app shows a short summary of the main terms of the Terms of Use, the
Privacy Policy and the Consent in Kazakh and in Russian, for information. The
English documents govern.

| Document | What it does | File |
|---|---|---|
| Terms of Use | the contract for using the LUME service (the relay and accounts) and the LUME name and logo | [TERMS.md](TERMS.md) |
| Privacy Policy | the operator's policy on personal data, and the information owed to users under Kazakh law and the GDPR | [PRIVACY.md](PRIVACY.md) |
| Consent to the processing of personal data | the consent given in the app when an account is created, the ground for processing under Kazakh law | [CONSENT.md](CONSENT.md) |
| The LUME website: privacy and terms of use | what the website stores and receives, what LUME Inc. does with what people send it, and the terms for using the website | [WEBSITE.md](WEBSITE.md) |
| Deleting your account | how to delete an account in the app, how to ask without it, and what is kept | [ACCOUNT-DELETION.md](ACCOUNT-DELETION.md) |
| Child Safety Standards | the rules against child sexual abuse and exploitation, which are part of the Terms of Use, and how to report it | [CHILD-SAFETY.md](CHILD-SAFETY.md) |
| Law Enforcement Policy | what LUME Inc. can give to public authorities, and how it responds | [LAW-ENFORCEMENT.md](LAW-ENFORCEMENT.md) |
| Permissions and background behaviour | what the official apps ask the operating system for | [PERMISSIONS.md](PERMISSIONS.md) |
| App store disclosures | the answers given in each store's data and content forms | [STORE-DISCLOSURES.md](STORE-DISCLOSURES.md) |
| Contact and company details | how to reach LUME Inc., and the points of contact the law requires | [CONTACT.md](CONTACT.md) |

Related, at the repository root: [SECURITY.md](../SECURITY.md) (vulnerability
reporting and good-faith research), [TRADEMARKS.md](../TRADEMARKS.md) (the
LUME name and logo), [LICENSE](../LICENSE) (AGPL-3.0-only for the code) and
[CONTRIBUTING.md](../CONTRIBUTING.md) (contributor licence agreement).

## When the documents apply

**WEBSITE.md is in effect**, because the website is live. It applies from the
day each version is published.

**All other documents are drafts** until the first public release of LUME, and
take effect on that day. They describe LUME as it will be when it is released.
Before that release they need the contact addresses, the hosting provider of
the relay (whose database for users in Kazakhstan must be located in
Kazakhstan), the EU representative, the trademark filing, the summary in
Kazakh and Russian on the screen where the user accepts, a way to sign a
request about an account with its key, including a deletion request made
without the app, and a review by a lawyer admitted in Kazakhstan. Each fact
that is not settled yet is an *Important* note starting with **To be filled in
before release**; `python site/build.py` lists how many each document has
left.

## Which document prevails

1. On the contract between a user and LUME Inc., the
   [Terms of Use](TERMS.md) prevail over the other documents. The
   [Child Safety Standards](CHILD-SAFETY.md) and the good-faith research rules
   in [SECURITY.md](../SECURITY.md) are part of the Terms of Use and bind every
   user; they change only with a new version of the Terms of Use.
2. On the processing of personal data, the
   [Consent to the processing of personal data](CONSENT.md) and the
   [Privacy Policy](PRIVACY.md) prevail over the other documents. Where the
   two differ, the narrower one applies: we process personal data only as far
   as both allow.
3. The other documents explain or apply the Terms of Use, the Privacy Policy
   and the Consent, and, to the extent the law allows, do not add to them or
   change them. The Child Safety Standards and the good-faith research rules
   are the exception: they are part of the Terms of Use (point 1).
4. The [GNU Affero General Public License v3.0](../LICENSE) governs the source
   code, and none of these documents limits the rights it gives anyone. The
   [LUME brand licence](../LICENSES/LicenseRef-LUME-Brand.txt) governs the
   LUME name and logo, as [TRADEMARKS.md](../TRADEMARKS.md) explains.

## Which law

The documents are written for the law of the Republic of Kazakhstan first,
above all the Law "On Personal Data and Their Protection" (No. 94-V, as
amended in 2026), the Law "On Consumer Protection" and the Law "On Online
Platforms and Online Advertising". They also give what the EU General Data
Protection Regulation and the Digital Services Act require of a service
offered in the EU. Where a user has a right that the law does not allow a
contract to take away, the documents keep it.

## How the documents are kept

The website is built from these files by `site/build.py`; nothing is copied by
hand. Every change is made in the public repository, where the whole history of
each document can be seen.

LUME Inc. numbers each published set of the Terms of Use (with the Child Safety
Standards and the good-faith research rules, which are part of them), the
Privacy Policy and the Consent. The user accepts them by pressing *I accept*
in the app. When an account is created, the app sends the number of the
version the user accepted, and the relay keeps that number and the day of
acceptance with the account. The relay tells the app the number of the version
in effect; when it is higher than the one accepted, the app shows the new
version and asks the user to accept it, and that acceptance is recorded the
same way. The relay refuses to create an account for a version that is no
longer current (sections 4.2, 5 and 7 of the [protocol](../docs/PROTOCOL.md)).
With software other than the official apps, registering an account is
acceptance by conduct (article 396(3) of the Civil Code of the Republic of
Kazakhstan), and that software must show the documents and send the number of
their version before it registers.

These documents describe what the software does. If the code and a document
disagree, that is a defect to fix before release, never a document to leave as
written.
