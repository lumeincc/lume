<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# App store disclosures

LUME's answers to each store's data and content forms. They are derived from
the [Privacy Policy](PRIVACY.md) and the [permissions](PERMISSIONS.md); if
either changes, this page changes in the same commit.
Русская версия: [STORE-DISCLOSURES.ru.md](STORE-DISCLOSURES.ru.md).
Қазақша нұсқа: [STORE-DISCLOSURES.kk.md](STORE-DISCLOSURES.kk.md).

## Google Play — Data safety

| Question | Answer |
|---|---|
| Does the app collect or share user data? | Yes — collects; shares with no one |
| **Personal info → User IDs** | **Collected**: the username. Not shared. Required. Purposes: app functionality, account management. Not processed ephemerally |
| **Device or other IDs** | **Collected**: the account and device public keys the app creates. Not shared. Required. Purposes: app functionality, account management, fraud prevention |
| Messages, photos, videos, files | Transmitted only end-to-end encrypted; LUME Inc. cannot read them. Under Play's rules, end-to-end encrypted data does not count as collected — check the current Play Console help before submitting |
| IP address | Processed ephemerally, in memory, for delivery and abuse protection; not stored |
| Location, contacts, financial info, health, app activity, web browsing, diagnostics | Not collected |
| Sharing with third parties | No |
| Encrypted in transit | Yes |
| Users can request deletion | Yes — *Delete account* in the app removes all server data at once; the web page stores require is [ACCOUNT-DELETION.md](ACCOUNT-DELETION.md) |
| Independent security review | Not yet — will be updated when one is done |

Other Play declarations:

- **Target audience:** 16+, not designed for children.
- **Content rating:** users can interact and share content.
- **Child safety standards:** published at [CHILD-SAFETY.md](CHILD-SAFETY.md),
  with in-app reporting and a responsible contact.
- **Foreground service:** type `remoteMessaging`, only when the user turns on
  *Background connection*.
- **Ads:** none.

## Microsoft Store

- Privacy policy: [PRIVACY.md](PRIVACY.md) (required for apps that use the
  network).
- Capabilities: `internetClient` only.
- Age rating through the IARC questionnaire: users interact, no purchases.

## Stores not yet decided

Publishing in stores aimed at other countries — for example RuStore — means
offering the service to users in those countries and may bring their laws on
messengers into play, some of which cannot be met without breaking end-to-end
encryption. Such publication waits for a separate decision by LUME Inc., taken
with a lawyer.

> [!IMPORTANT]
> **To be filled in before release:** the website addresses of the privacy
> policy and the account deletion page that each store requires.

## Not applicable

- **Refund policy:** there are no purchases — section 9 of the
  [Terms of Use](TERMS.md).
- **Enterprise device management (MDM / MAM):** LUME offers no managed
  configuration or app protection policies — it is a messenger for private
  individuals.
