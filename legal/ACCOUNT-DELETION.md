<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Deleting your LUME account

**Status: draft.** Takes effect with the first public release.
Русская версия: [ACCOUNT-DELETION.ru.md](ACCOUNT-DELETION.ru.md).
Қазақша нұсқа: [ACCOUNT-DELETION.kk.md](ACCOUNT-DELETION.kk.md).

## 1. From the app

Open the app's settings, choose *Delete account* and confirm. Your device signs
the request with your account key, and the relay deletes the account at once
and closes the connection. Deleting the account also withdraws your
[consent to the processing of personal data](CONSENT.md).

## 2. What is deleted

Everything our server holds about the account, in one step — every row of
section 3 of the [Privacy Policy](PRIVACY.md) that belongs to it:

- the username, public keys, generation number and discoverability setting;
- the day the account was created and the day it last connected;
- records that one-time keys were handed out;
- delivery tokens and invite codes;
- messages and attachments awaiting delivery to you.

Deleted records are overwritten in the server's database, not just marked as
deleted.

After that, the username is held for 31 days — only its hash is stored — and
then anyone can register it. People who already have you as a contact know you
by your keys, so the name's new holder cannot pass as you.

## 3. What is not deleted

- **What is on your device.** Messages, contacts and keys stay on your phone or
  computer until you remove the app or its data.
- **Copies your contacts hold.** Messages you sent are stored on your contacts'
  devices; we have no access to them.
- **Reports.** If another user reported messages from your account, the report
  is kept for 90 days, or longer where the law requires it — see the
  [Child Safety Standards](CHILD-SAFETY.md).
- **A barred name.** If the account was deleted for abuse and its name barred,
  the name's hash is kept while the bar lasts.

## 4. Without the app

We know nothing about you except your account keys, so we cannot confirm by
e-mail or phone that an account is yours, and we never delete an account
without a request signed by its key.

- **If you still have your recovery phrase**, install LUME on any device,
  recover the account from the phrase and delete it in the app. Recovery also
  disconnects the old device.
- **If you have neither the device nor the phrase**, no one — including us —
  can act for the account any more. It is deleted automatically 365 days after
  it last connected.

## 5. Deleting some data without deleting the account

- **Turn off search by name**, so no one can find your username.
- **Revoke a contact's delivery token** — their messages stop reaching you.
- **Delete a conversation** on your device; once delivered, it is not on our
  server.
