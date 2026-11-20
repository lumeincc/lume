<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# App store disclosures

These are LUME's answers to each store's data and content forms. They follow
from the [Privacy Policy](PRIVACY.md), the
[Consent to the processing of personal data](CONSENT.md) and the
[permissions](PERMISSIONS.md); if any of them changes, this page changes in the
same commit. If this page and the Privacy Policy or the Consent ever disagree,
they prevail and this page is corrected. The apps are not released yet, so
none of these answers has been submitted.

The stores ask for two web pages: the Privacy Policy and the account deletion
page. Both name the app, LUME, and its developer, LUME Inc.

> [!IMPORTANT]
> **To be filled in before release:** the web addresses of the Privacy Policy
> and of the account deletion page that each store requires, and the developer
> name as listed in each store. The current addresses are provisional:
> <https://lumeincc.github.io/lume/legal/privacy/> for the Privacy Policy and
> <https://lumeincc.github.io/lume/legal/account-deletion/> for the account
> deletion page.

## Google Play — Data safety

| Question | Answer |
|---|---|
| Does the app collect or share user data? | Yes, it collects data. It shares data with no one |
| **Personal info → User IDs** | **Collected**: the username. Not shared. Required. Purposes: app functionality, account management. Not processed ephemerally |
| **Device or other IDs** | **Collected**: the account and device public keys that the app creates, and the account ID that the relay assigns. Not shared. Required. Purposes: app functionality, account management, fraud prevention |
| Messages, photos, videos, files | Sent only end-to-end encrypted; LUME Inc. cannot read them. Under Play's rules, end-to-end encrypted data does not count as collected; check the current Play Console help before submitting. The exception is a report: if a user reports messages, the app sends those messages and the sender's identity keys sealed to LUME Inc.'s report key, so LUME Inc. can read them. Optional, started by the user. Purposes: safety and compliance. Kept for 90 days, or longer where the law requires |
| IP address | Processed ephemerally, in memory, for delivery and abuse protection, and never written to disk. For a message from a stranger without an invite, the relay keeps a hash of the sender's network block, keyed with a key that changes daily, and deletes it with the message |
| Other account data | Kept with the account and declared with it, for account management: the day the account was created and the day it last connected, the number of the version of the Terms of Use, the Privacy Policy and the Consent the user accepted and the day of acceptance, any measure on the account and the day it ends, and notices waiting for the account (at most 20, for at most 30 days). Play has no separate data type for these; check the current Play Console help before submitting |
| Location, contacts, financial info, health, app activity, web browsing, diagnostics | Not collected |
| Sharing with third parties | No |
| Encrypted in transit | Yes |
| Users can request deletion | Yes. *Delete account* in the app deletes the account and all server data linked to it in one step. [ACCOUNT-DELETION.md](ACCOUNT-DELETION.md) is the web page the store requires. It names the app and its developer and lists what is kept. It explains that anyone can write to us without the app, but that we delete an account only on a request signed with that account's key, and that today only the app can sign one. An account that has not connected for 365 days is deleted automatically, with all server data linked to it |
| Independent security review | Not yet. This answer will be updated after one |

> [!IMPORTANT]
> **To be filled in before release.** Google Play requires that a user can
> request deletion of an account without reinstalling the app. Today a
> deletion request made without the app cannot be signed, so the account
> cannot be deleted on it (section 4 of the
> [account deletion page](ACCOUNT-DELETION.md)). A way to sign a deletion
> request without the app is needed before the Data safety form is submitted,
> and this row then changes.

Other Play declarations:

- **Target audience:** 18 and over. LUME is for adults only and is not
  designed for children.
- **Content rating:** users can interact and share content.
- **Child safety standards:** published at [CHILD-SAFETY.md](CHILD-SAFETY.md),
  with in-app reporting and a designated contact.
- **Foreground service:** type `remoteMessaging`, only when the user turns on
  *Background connection*.
- **Ads:** none.

## Microsoft Store

- Privacy policy: [PRIVACY.md](PRIVACY.md). It is required because the app
  collects and transmits personal data, and for a desktop app in any case.
- Age rating through the IARC questionnaire: users interact, no purchases.
  LUME is for adults only: every user must be at least 18
  ([Terms of Use](TERMS.md)).

> [!IMPORTANT]
> **To be filled in before release:** how the Windows app is packaged and the
> capabilities it declares, the same as in the [permissions](PERMISSIONS.md).

## Stores not yet decided

Publishing in a store aimed at another country, such as RuStore, means offering
the service to users in that country. Its laws on messengers may then apply,
and some of them cannot be met without breaking end-to-end encryption. LUME
Inc. will decide on any such store separately, with legal advice.

## Not applicable

- **Refund policy:** there are no purchases; LUME is free (see the
  [Terms of Use](TERMS.md)).
- **Enterprise device management (MDM and MAM):** LUME offers no managed
  configuration or app protection policies.
