// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260621-008 — a one-time prekey must only be consumed after the first
 * inbound X3DH message authenticates. Looking it up must not delete it; a failed
 * decrypt leaves it intact; a successful decrypt consumes exactly one.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import 'fake-indexeddb/auto';
import { clear } from 'idb-keyval';

import {
  deriveMasterKeyFromPin,
  savePreKeyMaterial,
  loadPreKeyMaterial,
  findOneTimePreKey,
  deleteOneTimePreKey,
} from '@/crypto/storage';
import { generateExchangeKeyPair } from '@/crypto/keys';

beforeEach(async () => {
  await clear();
});

describe('one-time prekey consume timing (SEC-20260621-008)', () => {
  it('findOneTimePreKey does not consume; deleteOneTimePreKey consumes exactly one', async () => {
    const mk = await deriveMasterKeyFromPin('1234');
    const opk = generateExchangeKeyPair();
    await savePreKeyMaterial(
      { signedPreKey: generateExchangeKeyPair(), oneTimePreKeys: [opk], updatedAt: Date.now() },
      mk,
    );

    // Failed-decrypt simulation: look up the OPK but do NOT delete → still present.
    const found = await findOneTimePreKey(opk.publicKey, mk);
    expect(found?.publicKey).toBe(opk.publicKey);
    expect((await loadPreKeyMaterial(mk))!.oneTimePreKeys).toHaveLength(1);

    // A second failed attempt also leaves it intact (no depletion from bogus messages).
    await findOneTimePreKey(opk.publicKey, mk);
    expect((await loadPreKeyMaterial(mk))!.oneTimePreKeys).toHaveLength(1);

    // Successful-decrypt simulation: delete after use → consumed exactly one.
    await deleteOneTimePreKey(opk.publicKey, mk);
    expect((await loadPreKeyMaterial(mk))!.oneTimePreKeys).toHaveLength(0);
    expect(await findOneTimePreKey(opk.publicKey, mk)).toBeNull();
  });
});
