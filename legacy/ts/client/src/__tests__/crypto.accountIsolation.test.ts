// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * A new account on a device must not inherit the previous one's store.
 *
 * Both failure modes below were reported from a real install:
 *
 *   - with the SAME pin the encryption salt is reused, so the derived master key
 *     is identical and the previous account's contacts and chats decrypt straight
 *     into the new one — one person's conversations under another's login;
 *   - with a DIFFERENT pin those records stop opening, the first loader raises a
 *     StorageIntegrityError, and persistence latches off for the session
 *     ("Не удалось прочитать локальные данные. Сохранение отключено…").
 *
 * `resetVaultForNewAccount()` is what setup and recovery call to prevent both.
 */

import { describe, it, expect, beforeEach } from "vitest";
import "fake-indexeddb/auto";
import {
  deriveMasterKeyFromPin,
  saveContacts,
  loadContacts,
  saveChats,
  loadChats,
  saveIdentityKeys,
  loadIdentityKeys,
  savePinHash,
  hasAccount,
  resetVaultForNewAccount,
  clearCachedMasterKey,
  hasStorageIntegrityFailure,
  type Contact,
} from "@/crypto/storage";
import { generateIdentityKeys } from "@/crypto/keys";
import { clear } from "idb-keyval";

const PIN_A = "112233";
const PIN_B = "998877";

const contact: Contact = {
  id: "contact-1",
  username: "friend",
  publicKey: "pk",
  exchangeKey: "ek",
  addedAt: 1,
};

/** Everything setup writes for one account, in the same order. */
async function createAccount(pin: string) {
  await resetVaultForNewAccount();
  const identity = generateIdentityKeys();
  const masterKey = await deriveMasterKeyFromPin(pin);
  await saveIdentityKeys(identity, masterKey);
  await savePinHash(pin);
  return { identity, masterKey };
}

describe("account isolation", () => {
  beforeEach(async () => {
    await clear();
    clearCachedMasterKey();
  });

  it("a second account with the SAME pin cannot read the first one's contacts or chats", async () => {
    const first = await createAccount(PIN_A);
    await saveContacts([contact], first.masterKey);
    await saveChats(
      [{ id: "c1", contactId: "contact-1", lastMessage: "секрет", updatedAt: 1, unreadCount: 0 }] as never,
      first.masterKey,
    );

    // Same PIN is the dangerous case: without a reset the key derivation lands
    // on the very same master key.
    const second = await createAccount(PIN_A);

    expect(await loadContacts(second.masterKey)).toEqual([]);
    expect(await loadChats(second.masterKey)).toEqual([]);
  });

  it("a second account with a DIFFERENT pin opens cleanly instead of latching an integrity failure", async () => {
    const first = await createAccount(PIN_A);
    await saveContacts([contact], first.masterKey);

    const second = await createAccount(PIN_B);

    expect(await loadContacts(second.masterKey)).toEqual([]);
    expect(hasStorageIntegrityFailure()).toBe(false);
  });

  it("stores the new identity, not the replaced one", async () => {
    const first = await createAccount(PIN_A);
    const second = await createAccount(PIN_A);

    const stored = await loadIdentityKeys(second.masterKey);
    expect(stored?.signing.publicKey).toBe(second.identity.signing.publicKey);
    expect(stored?.signing.publicKey).not.toBe(first.identity.signing.publicKey);
  });

  it("mints a fresh salt, so the same pin yields a different master key", async () => {
    const first = await createAccount(PIN_A);
    const second = await createAccount(PIN_A);

    const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
    expect(hex(second.masterKey)).not.toBe(hex(first.masterKey));
  });

  it("leaves no account behind after the reset alone", async () => {
    await createAccount(PIN_A);
    expect(await hasAccount()).toBe(true);

    await resetVaultForNewAccount();
    expect(await hasAccount()).toBe(false);
  });
});
