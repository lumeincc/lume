// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260621-004 — attachment decrypt keys live in the key vault (keyed by
 * fileId), never in Zustand/message state.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';

import {
  vaultSetAttachmentKey,
  vaultGetAttachmentKey,
  vaultGetAllAttachmentKeys,
  vaultSetAttachmentKeys,
  vaultClear,
} from '@/crypto/keyVault';

beforeEach(() => {
  vaultClear();
});

describe('attachment key vault (SEC-20260621-004)', () => {
  it('stores and retrieves attachment keys by fileId', () => {
    vaultSetAttachmentKey('f1', 'k1', 'n1');
    expect(vaultGetAttachmentKey('f1')).toEqual({ key: 'k1', nonce: 'n1' });
    expect(vaultGetAttachmentKey('missing')).toBeUndefined();
  });

  it('bulk-loads keys and clears them on vaultClear', () => {
    vaultSetAttachmentKeys({
      a: { key: 'ka', nonce: 'na' },
      b: { key: 'kb', nonce: 'nb' },
    });
    expect(Object.keys(vaultGetAllAttachmentKeys())).toHaveLength(2);

    vaultClear();
    expect(vaultGetAttachmentKey('a')).toBeUndefined();
    expect(Object.keys(vaultGetAllAttachmentKeys())).toHaveLength(0);
  });

  it('MessageAttachment (kept in Zustand) carries no raw decrypt key/nonce', () => {
    const src = readFileSync(new URL('../stores/index.ts', import.meta.url), 'utf8');
    const start = src.indexOf('export interface MessageAttachment');
    const end = src.indexOf('}', start);
    const iface = src.slice(start, end);
    expect(iface).not.toMatch(/\bkey\b/);
    expect(iface).not.toMatch(/\bnonce\b/);
  });
});
