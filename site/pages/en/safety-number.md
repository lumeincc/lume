<!--
SPDX-FileCopyrightText: 2026 LUME Inc.
SPDX-License-Identifier: AGPL-3.0-only
-->

# Verify a contact with the safety number

When you add a contact on LUME, your app receives their keys through the relay.
The **safety number** lets you check, outside LUME, that those keys really
belong to the person you think — so that nobody, including whoever runs the
relay, can quietly put themselves in the middle.

> [!NOTE]
> The LUME apps have not been released yet. This page explains how
> verification works; the exact buttons will be described here once the apps
> exist.

## What a safety number is

- **60 digits in 12 groups of five**, also shown as a QR code.
- It is calculated from both people's identity keys, so you and your contact
  see **the same number** for your conversation.
- It changes only if one of you starts a new account. Recovering the same
  account on a new device with its recovery phrase keeps the same identity keys,
  and so the same number.

## Why it matters

A contact's username is confirmed by a certificate the relay signs. That stops
most mistakes, but whoever controls the relay's signing key could attach a
username to the wrong keys. Comparing safety numbers is the one check that does
not depend on the relay ([§1](/spec/crypto/#1-goals-and-non-goals),
[§12](/spec/crypto/#12-pinning-safety-numbers-and-invites)).

## How to compare

1. **In person, if you can.** Open the contact's safety number on both devices
   and let one of you scan the other's QR code. The camera is used only while
   you scan, and the picture never leaves the device
   ([Permissions](/legal/permissions/)).
2. **At a distance**, read the digits to each other over a channel where you
   can recognise the other person, such as a voice or video call. Do not compare
   them in a LUME message to the same contact: if someone were in the middle,
   they could change the number in the message.
3. **Compare all 60 digits**, not only the first few.

## If the numbers match

You are talking to the account you meant to. LUME already **pins** a contact's
keys the first time it accepts them: if different keys ever appear for that
contact later, LUME refuses them instead of showing a warning you could click
away ([§12](/spec/crypto/#12-pinning-safety-numbers-and-invites)). Comparing
the safety number confirms that the keys it pinned were the right ones.

## If they do not match

- Do not share anything sensitive in that conversation.
- Check that you are both looking at the same conversation.
- A mismatch means the keys you have are not the keys your contact has: you are
  talking to a different account than you think, or someone is in between.
  Reach the person another way and ask.

## Invite links

An invite link carries a short fingerprint of the inviter's keys, and LUME
refuses to connect if the keys it receives do not match it. So when you get an
invite link through a channel you trust — in person, or from someone you know —
the first contact is authenticated without comparing digits
([§12](/spec/crypto/#12-pinning-safety-numbers-and-invites)). A link from a
source you do not trust proves only that you reached whoever sent the link.

## For the technically curious

Each person's half is 5,200 rounds of SHA-512 over their two public identity
keys, cut into 30 digits. The two halves are put in a fixed order, so both
devices show the same 60 digits. The exact construction is in
[§12 of the specification](/spec/crypto/#12-pinning-safety-numbers-and-invites).
