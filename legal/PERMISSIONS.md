<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Permissions and background behaviour

**Status: draft.** It describes the official LUME apps as they will be at the
first public release. The apps are not built yet.

This page lists what the official LUME apps, published by LUME Inc. in its own
name, ask the operating system for. For Android it is the complete list: a
build that asks for anything else does not follow this page, and that is a
bug. An official app that someone passes on unmodified, exactly as LUME Inc.
published it, is still an official app. Builds that anyone else modifies and
distributes under the source code licence are not official LUME apps, and this
page does not describe them. Nor does it describe other software that connects
to the LUME relay under the [Terms of Use](TERMS.md). If a later version of an
official app needs another permission, this page changes before that version is
released.

## Android

| Permission | When it is asked | Why |
|---|---|---|
| `INTERNET` | at install, without a prompt | to connect to the LUME relay |
| `POST_NOTIFICATIONS` (Android 13 and later) | the first time you turn notifications on | to show that a message has arrived; the notification shows the contact's name only if you allow previews |
| `CAMERA` | only when you tap *Scan code* | to scan a contact's QR code, to compare safety numbers or to open an invite; frames are processed on the device and never stored or sent |
| `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_REMOTE_MESSAGING` | only if you turn *Background connection* on | to keep the connection open while the app is closed, with the permanent notification that Android requires |
| `RECEIVE_BOOT_COMPLETED` | only if *Background connection* is on | to reopen that connection after the phone restarts |

If you refuse a permission, only the feature that needs it is unavailable.

**Never requested:** contacts, location, microphone, phone, SMS, call log,
accounts, files or photos, and *ignore battery optimisations*. You choose
attachments through the system photo and file pickers, which need no
permission. Where the device supports it, the app keeps a key in the secure
hardware of the Android Keystore, which also needs no permission.

The list does not count a permission that the app defines only for its own
components, which only apps signed with the same key can hold. Such a
permission gives no access to your data or your device.

### Background and battery

LUME does not use Google's push service, because that would tell Google when
you receive messages. Messages reach the app only over its own connection to
the relay. So:

- **By default**, messages arrive while the app is open, and messages that
  waited on the relay are fetched as soon as you open it. Nothing runs in the
  background, so the app uses no battery while it is closed.
- **With *Background connection* on**, the app keeps one connection to the
  relay open and shows a permanent notification. Some manufacturers' battery
  savers still stop it. You can exempt LUME in the system battery settings
  yourself; the app does not ask for that exemption.

### Other protections

- **Backups:** the app opts out of Android cloud backup and device-to-device
  transfer (`allowBackup="false"` and data extraction rules that exclude
  everything), so your encrypted data is not copied to Google.
- **Screen security** (on by default): screenshots and screen recordings of the
  app are blocked, and its content is hidden in the recent apps view. You can
  turn this off in Settings.
- **Keyboard:** message fields ask the keyboard not to learn from what you type
  (`IME_FLAG_NO_PERSONALIZED_LEARNING`). Whether the keyboard follows that
  request depends on the keyboard you use.

## Windows

> [!IMPORTANT]
> **To be filled in before release.** How the Windows app is built and
> packaged, and the complete list of capabilities or other permissions it
> declares. Until then this page makes no statement about them.

Notifications use the Windows notification system.

Local data is kept in an encrypted vault (section 10 of the
[cryptography specification](../docs/CRYPTO.md)). Its key is derived from your
passphrase and, on a computer with a TPM 2.0, from a key that cannot leave the
TPM. Without a usable TPM, a random secret protected with Windows DPAPI for
your user account takes the TPM's place, and the app tells you so. The vault is
kept only on the computer and is not placed where Windows copies it to other
computers.
