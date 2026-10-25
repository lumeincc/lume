// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260621-009 — the hidden-chat PIN hash must never be persisted unencrypted.
 * saveSettings must fail closed when no master key is provided.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';
import { clear, get, set } from 'idb-keyval';

import {
  saveSettings,
  loadSettings,
  deriveMasterKeyFromPin,
  hashHiddenChatPin,
  verifyHiddenChatPin,
} from '@/crypto/storage';

const HIDDEN_CHAT_PIN_KEY = 'hidden_chat_pin';

beforeEach(async () => {
  await clear();
});

const base = {
  theme: 'light' as const,
  notifications: true,
  selfDestructDefault: null,
  hiddenChatsEnabled: true,
};

describe('saveSettings hidden PIN hardening (SEC-20260621-009)', () => {
  it('refuses to persist hiddenChatPinHash without a master key (no plaintext fallback)', async () => {
    await expect(saveSettings({ ...base, hiddenChatPinHash: 'legacy-plain-hash' })).rejects.toThrow();
    // Nothing was written that a pre-auth load could surface.
    expect((await loadSettings()).hiddenChatPinHash).toBeUndefined();
  });

  it('stores the hash encrypted when a master key is provided', async () => {
    const mk = await deriveMasterKeyFromPin('1234');
    await saveSettings({ ...base, hiddenChatPinHash: 'h' }, mk);
    expect((await loadSettings(mk)).hiddenChatPinHash).toBe('h');
    // Without the key it is not plaintext-readable.
    expect((await loadSettings()).hiddenChatPinHash).toBeUndefined();
  });
});

describe('loadSettings legacy plaintext hidden PIN (SEC-20260621-009)', () => {
  it('omits a legacy plaintext hash and does not migrate it when no master key is supplied', async () => {
    // Simulate a legacy install: a raw plaintext hash string at rest.
    await set(HIDDEN_CHAT_PIN_KEY, 'legacy-plain-hash');

    const settings = await loadSettings();

    // Pre-auth read must never surface the legacy hash...
    expect(settings.hiddenChatPinHash).toBeUndefined();
    // ...and must leave it untouched (still a string, not migrated/encrypted).
    expect(await get(HIDDEN_CHAT_PIN_KEY)).toBe('legacy-plain-hash');
  });

  it('migrates and returns a legacy plaintext hash only when a master key is supplied', async () => {
    await set(HIDDEN_CHAT_PIN_KEY, 'legacy-plain-hash');
    const mk = await deriveMasterKeyFromPin('1234');

    const settings = await loadSettings(mk);

    // Authenticated read returns the hash...
    expect(settings.hiddenChatPinHash).toBe('legacy-plain-hash');
    // ...and the at-rest value is now encrypted (v2 object), no longer plaintext.
    const stored = await get(HIDDEN_CHAT_PIN_KEY);
    expect(typeof stored).toBe('object');
    expect((stored as { v?: number }).v).toBe(2);
    // A subsequent pre-auth read still cannot recover it.
    expect((await loadSettings()).hiddenChatPinHash).toBeUndefined();
  });
});

/**
 * The iteration count in a stored hash is untrusted input.
 *
 * `verifyHiddenChatPin` reads "salt:iterations:hash" out of IndexedDB and used to
 * pass the middle segment straight to PBKDF2 after a bare `parseInt`. Anything
 * able to write to IndexedDB — XSS, or a shared device — therefore chose the
 * argument to the KDF.
 *
 * Measured, not assumed. Without the bounds check WebCrypto raises rather than
 * returning, so the failure is a *throw out of a boolean function*, which the
 * hidden-chat unlock path does not expect:
 *
 *   "salt:0:hash"            OperationError: iterations cannot be zero
 *   "salt:99999999999:hash"  TypeError: 'iterations' is outside the expected range
 *   "salt:not-a-number:hash" TypeError: 'iterations' is not a finite number
 *
 * A single low count such as "salt:1:hash" is *not* a break on its own — the
 * digest then simply fails to match — so the floor is defence in depth, while the
 * upper and non-finite bounds fix a real crash.
 *
 * The same class of bug was already fixed for backup envelopes in this file
 * (MIN/MAX_BACKUP_ITERATIONS, SEC-20260721-006). This sibling path was missed.
 * Found while removing the non-null assertions from this file, not reported.
 */
describe('verifyHiddenChatPin bounds the stored iteration count', () => {
  const pin = 'correct-horse-battery';

  it('accepts a hash it produced itself, and refuses the wrong PIN', async () => {
    const stored = await hashHiddenChatPin(pin);
    expect(await verifyHiddenChatPin(pin, stored)).toBe(true);
    expect(await verifyHiddenChatPin('wrong-pin', stored)).toBe(false);
  });

  it('returns false for a zero or negative count instead of throwing', async () => {
    const stored = await hashHiddenChatPin(pin);
    const [salt, , hash] = stored.split(':');
    expect(await verifyHiddenChatPin(pin, `${salt}:0:${hash}`)).toBe(false);
    expect(await verifyHiddenChatPin(pin, `${salt}:-600000:${hash}`)).toBe(false);
  });

  it('returns false below the legacy floor rather than deriving weakly', async () => {
    const stored = await hashHiddenChatPin(pin);
    const [salt, , hash] = stored.split(':');
    expect(await verifyHiddenChatPin(pin, `${salt}:1:${hash}`)).toBe(false);
  });

  it('returns false for an absurd count instead of throwing or hanging', async () => {
    const stored = await hashHiddenChatPin(pin);
    const [salt, , hash] = stored.split(':');
    expect(await verifyHiddenChatPin(pin, `${salt}:99999999999:${hash}`)).toBe(false);
  });

  it('returns false for a non-numeric count instead of passing NaN to PBKDF2', async () => {
    const stored = await hashHiddenChatPin(pin);
    const [salt, , hash] = stored.split(':');
    expect(await verifyHiddenChatPin(pin, `${salt}:not-a-number:${hash}`)).toBe(false);
    expect(await verifyHiddenChatPin(pin, `${salt}::${hash}`)).toBe(false);
  });

  it('still parses the legacy two-segment format, and refuses malformed input', async () => {
    // Legacy hashes carry no iteration field and are pinned to 100k, so they are
    // not a downgrade vector — but they must keep being parsed rather than throw.
    expect(await verifyHiddenChatPin(pin, 'AAAA:BBBB')).toBe(false);
    expect(await verifyHiddenChatPin(pin, 'only-one-segment')).toBe(false);
  });
});
