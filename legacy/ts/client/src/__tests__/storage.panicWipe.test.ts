// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260621-016 — after a panic wipe, persistence must be disabled so a
 * pending/in-flight debounced save cannot re-create the data that was cleared.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';
import { clear } from 'idb-keyval';

import {
  deriveMasterKeyFromPin,
  saveChats,
  loadChats,
  saveContacts,
  loadContacts,
  panicWipe,
} from '@/crypto/storage';
import type { Chat } from '@/stores';

beforeEach(async () => {
  await clear();
});

const chat: Chat = {
  id: 'c1',
  contactId: 'u1',
  messages: [],
  unreadCount: 0,
  isHidden: false,
};
const contact = {
  id: 'u1',
  username: 'alice',
  publicKey: 'pk',
  exchangeKey: 'ek',
  addedAt: 1,
};

describe('panic wipe disables persistence (SEC-20260621-016)', () => {
  it('a persist firing after panicWipe does not re-create cleared data', async () => {
    const mk = await deriveMasterKeyFromPin('1234');
    await saveChats([chat], mk);
    await saveContacts([contact], mk);
    expect((await loadChats(mk)).length).toBe(1);
    expect((await loadContacts(mk)).length).toBe(1);

    await panicWipe();

    // Simulate pending/in-flight debounced persist callbacks firing after the wipe.
    await saveChats([chat], mk);
    await saveContacts([contact], mk);

    expect(await loadChats(mk)).toEqual([]);
    expect(await loadContacts(mk)).toEqual([]);
  });

  it('deriving a fresh master key re-enables persistence', async () => {
    await deriveMasterKeyFromPin('1234');
    await panicWipe();

    // A fresh session (re-setup/unlock) re-derives the key, re-enabling writes.
    const mk2 = await deriveMasterKeyFromPin('5678');
    await saveChats([chat], mk2);
    expect((await loadChats(mk2)).length).toBe(1);
  });
});
