<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Deleting your LUME account

**Status: draft.** Takes effect with the first public release.
Русская версия: [ACCOUNT-DELETION.ru.md](ACCOUNT-DELETION.ru.md).

## 1. From the app

Open the app's settings, choose *Delete account* and confirm. Your device signs
the request with your account's key, and the relay deletes the account at once
and closes the connection.

## 2. What is deleted

Everything our server holds about the account, in one step — that is, every row
of section 3 of the [Privacy Policy](PRIVACY.md) that belongs to it:

- your username, public keys and discoverability setting;
- the day the account was created and the day it last connected;
- your delivery tokens and invite codes;
- messages and attachments waiting to be delivered to you.

Your username is then held for 31 days, stored only as a hash, and after that
anyone can register it. People who already have you as a contact recognise you
by your keys, so a new holder of the name cannot pass for you with them.

## 3. What is not deleted

- **What is on your device.** Messages, contacts and keys stay on your phone or
  computer until you remove the app or erase its data.
- **Your contacts' copies.** Messages you sent are stored on your contacts'
  devices; we have no access to them.
- **Reports.** If another user reported messages from your account, that report
  is kept for 90 days, or longer where the law requires it to be preserved — see
  the [Child Safety Standards](CHILD-SAFETY.md).

## 4. Without the app

We know nothing about you except your account's keys, so we cannot confirm by
e-mail or phone that an account is yours, and we never delete an account without
a request signed by its key.

- **If you still have your recovery phrase**, install LUME on any device,
  recover the account with the phrase and delete it from the app. Recovering
  also locks out the old device.
- **If you have neither the device nor the phrase**, nobody can act for the
  account any more, us included. It is deleted automatically 365 days after it
  last connected.

## 5. Deleting some data, not the whole account

- **Turn discoverability off**, so that no one can look your username up.
- **Revoke a contact's delivery token**, which stops their messages from reaching
  you.
- **Delete conversations** on your device; they were never on our server once
  delivered.
