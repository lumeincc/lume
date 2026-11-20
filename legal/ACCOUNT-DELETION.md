<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Deleting your LUME account

**Status: draft.** Takes effect with the first public release.

This page explains how to delete an account in **LUME**, the messenger
developed and run by **LUME Inc.** (ТОО «LUME Inc.», BIN 260740032421), what is
deleted and what is kept.

## 1. From the app

1. Open the app's settings, choose *Delete account* and confirm. Your app signs
   the request with your account key, and the relay deletes the account at once
   and closes the connection. This works also while the account is suspended.
2. Deleting the account also withdraws your
   [consent to the processing of personal data](CONSENT.md) and ends the
   [Terms of Use](TERMS.md) for that account. Processing stops at once, except
   as section 3 describes, sooner than the 15 working days the law allows.
3. Deletion is final. Neither you nor we can restore a deleted account or its
   data. Obligations under the Terms of Use that arose before deletion are not
   affected.

## 2. What is deleted

Everything our server holds about the account is deleted in one step. This
covers every row of section 3 of the [Privacy Policy](PRIVACY.md) that belongs
to the account:

- the username and the random account identifier that the server assigned to
  the account;
- the public keys, the generation number and the discoverability setting;
- the day the account was created and the day it last connected;
- the number of the version of the documents you accepted, and the day you
  accepted it;
- any measure on the account, and notices that have not yet reached it;
- the records that one-time keys were handed out;
- the hashes of delivery tokens and invite codes, with their state and days;
- messages awaiting delivery to you, with everything stored with them;
- attachments awaiting download by you.

Deleted records are overwritten in the server's database, not just marked as
deleted, and the attachment files are deleted.

After that, the username is held for 31 days, with only its hash stored, and
then anyone can register it. People who already have you as a contact know you
by your keys, so the name's new holder cannot pass as you.

## 3. What is not deleted

- **What is on your device.** Messages, contacts and keys stay on your phone or
  computer until you remove the app or its data.
- **Copies your contacts hold.** Messages you sent are stored on your contacts'
  devices, and we have no access to them.
- **Messages and attachments you sent that are still waiting for delivery.**
  The server does not record who sent them, so it cannot link them to your
  account. They are delivered or deleted within 30 days, like any others.
- **Reports.** If other users reported messages from your account, the reports
  are kept for the period section 3 of the [Privacy Policy](PRIVACY.md) gives.
  The server stores reports without linking them to an account, so deleting
  the account cannot find and delete them. See the
  [Child Safety Standards](CHILD-SAFETY.md).
- **A barred name.** If the account was deleted for abuse and its name was
  barred, the hash of the name is kept while the bar lasts.
- **Evidence preserved for the authorities.** If we delete an account for
  child sexual abuse or exploitation, or a competent authority has lawfully
  asked us to preserve data about it, we keep a copy of the account data and
  the reports for as long as the law requires or the authority lawfully asks,
  and then delete it. See the [Law Enforcement Policy](LAW-ENFORCEMENT.md).
- **What you wrote to us.** Messages you sent to the addresses on the
  [contact page](CONTACT.md), such as a claim, an appeal or a deletion request,
  are kept as the [Privacy Policy](PRIVACY.md) describes.

## 4. Without the app

1. You can write to us without installing the app, but we can delete an
   account only on a request signed with that account's key. Today the only
   way to sign such a request is the LUME app (clause 4.3). Write to the
   personal-data address on the [contact page](CONTACT.md) and name the
   username. We answer within the period the law sets and explain what you
   can do.
2. We hold no e-mail address or phone number for you, so the only proof that an
   account is yours is its key. We do not delete an account on the strength of
   a name, a message or a document alone, because anyone could then delete
   someone else's account.
3. **If you still have your recovery phrase**, install LUME on any device,
   recover the account from the phrase and delete it in the app. Recovery also
   disconnects the old device.
4. **If you have neither the device nor the phrase**, no one, including us, can
   act for the account any more. It is deleted automatically, without a
   decision by a person, 365 days after it last connected.

> [!IMPORTANT]
> **To be filled in before release.** A tool that signs a deletion request
> from the recovery phrase without the LUME app, and how to use it. Until it
> exists, clause 4.1 and the store declarations must not say that an account
> can be deleted without the app.

> [!IMPORTANT]
> **To be filled in before release.** The personal-data address on the
> [contact page](CONTACT.md), which is also the address for deletion requests
> made without the app.

## 5. Deleting some data without deleting the account

- **Turn off search by name.** Only people who have an invite from you, or who
  are already your contacts, can then look you up by your username.
- **Block a contact.** The server then discards their messages to you instead
  of storing them, and they are not told that you blocked them. So that they
  cannot tell, attachments they upload to you are still stored, unread, until
  their download limit is used up or they expire, after at most 30 days.
- **Delete a conversation** on your device. A message is deleted from our
  server as soon as your app confirms receiving it. An attachment stays until
  its download limit is used up, and for at most 30 days.

## 6. When we delete an account

We may also delete an account ourselves. What is deleted and kept is then the
same as in sections 2 and 3.

1. **Inactive accounts.** The server deletes an account automatically 365 days
   after it last connected. This is an automated measure: no person decides it,
   and it does not assess you or your content.
2. **Child sexual exploitation or a real threat to life.** If a report or other
   information clearly shows either, we delete the account and bar its
   username at once, as the [Child Safety Standards](CHILD-SAFETY.md) describe.
3. **Other breaches of the Terms of Use.** We first suspend the account and
   tell you in the app. We delete it only after the 30-day appeal period in
   section 6 of the [Terms of Use](TERMS.md) has passed, or your appeal has
   been rejected, unless the breach is serious and repeated.
4. **A court or a competent authority.** We carry out a lawful order to delete
   an account, as the [Law Enforcement Policy](LAW-ENFORCEMENT.md) describes.
5. **The end of the service.** If LUME Inc. stops the service, every account is
   deleted after notice in the app, as the [Terms of Use](TERMS.md) describe.
