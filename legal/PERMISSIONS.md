<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Permissions and background behaviour

**Status: draft**, for the first public release.
Русская версия: [PERMISSIONS.ru.md](PERMISSIONS.ru.md).
Қазақша нұсқа: [PERMISSIONS.kk.md](PERMISSIONS.kk.md).

This is the complete list of what the official LUME apps ask the operating
system for. A build that asks for anything else is not following this page and
is a bug.

## Android

| Permission | When it is asked | Why |
|---|---|---|
| `INTERNET` | at install (no prompt) | to connect to the LUME relay |
| `POST_NOTIFICATIONS` (Android 13+) | the first time you turn notifications on | to show that a message arrived; the notification shows the contact name only if you allow previews |
| `CAMERA` | only when you tap *Scan code* | to scan a contact's QR code for safety-number verification or an invite; frames are processed on the device and never stored or sent |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_REMOTE_MESSAGING` | only if you turn *Background connection* on | to keep the connection open while the app is closed, shown as a permanent notification as Android requires |
| `RECEIVE_BOOT_COMPLETED` | only if *Background connection* is on | to reopen that connection after the phone restarts |

**Never requested:** contacts, location, microphone, phone, SMS, call log,
accounts, files or photos (attachments are chosen through the system photo and
file pickers, which need no permission), and *ignore battery optimisations*.

### Background and battery

LUME does not use Google's push service, because that would tell Google when
you receive messages. So:

- **By default**, messages arrive while the app is open and are fetched the
  moment you open it. Nothing runs in the background and the battery cost is
  zero.
- **With *Background connection* on**, the app keeps one connection to the
  relay open and shows a permanent notification. Some manufacturers' battery
  savers still stop it; you can exempt LUME in the system battery settings
  yourself. The app does not ask for that exemption.

### Other protections

- **Backups:** the app opts out of Android cloud and device-to-device backup
  (`allowBackup="false"` and data-extraction rules excluding everything), so
  your encrypted data is not copied to Google.
- **Screen security** (on by default): screenshots and screen recording of the
  app are blocked and its content is hidden in the recent-apps view. You can
  turn it off in Settings.
- **Keyboard:** message fields ask the keyboard not to learn from what you type
  (`IME_FLAG_NO_PERSONALIZED_LEARNING`).

## Windows

The desktop app declares only the `internetClient` capability. Notifications use
Windows' own notification system and need no extra permission. Local data is
protected with Windows DPAPI for your user account and is excluded from
roaming.
