<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# App store disclosures

The answers LUME gives in each store's data and content forms, derived from the
[Privacy Policy](PRIVACY.md) and [Permissions](PERMISSIONS.md). When either of
those changes, this page changes in the same commit.
Русская версия: [STORE-DISCLOSURES.ru.md](STORE-DISCLOSURES.ru.md).

## Google Play — Data safety

| Question | Answer |
|---|---|
| Does the app collect or share user data? | Yes — collects one data type, shares none |
| **Personal info → User IDs** | **Collected**: the username. Not shared. Required. Purposes: app functionality, account management. Not processed ephemerally |
| Messages, photos, videos, files | Sent only with end-to-end encryption, unreadable by LUME Inc. Play's guidance does not count end-to-end-encrypted data as collected — confirm against the current Play Console help when submitting |
| IP address | Processed ephemerally, in memory, for delivery and abuse prevention; not stored |
| Location, contacts, financial info, health, app activity, web history, device or other IDs, diagnostics | Not collected |
| Data shared with third parties | None |
| Data encrypted in transit | Yes |
| Users can request deletion | Yes — *Delete account* in the app removes all server-side data at once; the web page every store asks for is [ACCOUNT-DELETION.md](ACCOUNT-DELETION.md) |
| Independent security review | No, not yet — will be updated if one is completed |

Other Play declarations:

- **Target audience:** 16 and over; not designed for children.
- **Content rating:** users can communicate with each other and share content.
- **Child Safety Standards:** published at [CHILD-SAFETY.md](CHILD-SAFETY.md),
  with in-app reporting and a designated contact.
- **Foreground service:** type `remoteMessaging`, used only when the user turns
  on *Background connection*.
- **Ads:** the app contains no ads.

## RuStore

- Category: Communications. Age rating: 16+.
- Privacy policy: [PRIVACY.ru.md](PRIVACY.ru.md).
- No payments, no ads, no third-party SDKs.

## Microsoft Store

- Privacy policy URL: [PRIVACY.md](PRIVACY.md) (required for apps that use the
  network).
- Capabilities: `internetClient` only.
- Age rating through the IARC questionnaire: users interact; no purchases.

> [!IMPORTANT]
> **To be filled in before release:** the website addresses of the privacy
> policy and of the account deletion page, which every store asks for.

## Not applicable

- **Refund policy:** there are no purchases — [Terms](TERMS.md) section 6.
- **Corporate device management (MDM / MAM):** LUME does not offer managed
  configuration or app-protection policies; it is a consumer messenger.
