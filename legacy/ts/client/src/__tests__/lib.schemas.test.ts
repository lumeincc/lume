// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-026 — client response schemas must validate key material by
 * decoded length, not accept any non-empty string.
 * SEC-20260721-025 — the WebSocket typing/read schemas must match the shape the
 * server actually broadcasts (the earlier placeholders did not, and no code used
 * them).
 */

import { describe, it, expect } from 'vitest';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';

import { UserBundleSchema, WsTypingSchema, WsReadReceiptSchema } from '@/lib/schemas';

const uuid = () => crypto.randomUUID();
const key32 = () => encodeBase64(nacl.randomBytes(32));
const sig64 = () => encodeBase64(nacl.randomBytes(64));

function bundle(overrides: Record<string, unknown> = {}) {
  return {
    id: uuid(),
    username: 'alice',
    identityKey: key32(),
    signedPrekey: key32(),
    signedPrekeySignature: sig64(),
    ...overrides,
  };
}

describe('SEC-20260721-026 — bundle schema validates key material', () => {
  it('accepts a well-formed bundle with real 32/64-byte keys', () => {
    expect(UserBundleSchema.safeParse(bundle()).success).toBe(true);
  });

  it('rejects a truncated (31-byte) signed prekey before it reaches crypto', () => {
    const b = bundle({ signedPrekey: encodeBase64(nacl.randomBytes(31)) });
    expect(UserBundleSchema.safeParse(b).success).toBe(false);
  });

  it('rejects a non-base64 identity key', () => {
    const b = bundle({ identityKey: 'not!valid!base64!!!' });
    expect(UserBundleSchema.safeParse(b).success).toBe(false);
  });

  it('rejects a 32-byte value where a 64-byte signature is required', () => {
    const b = bundle({ signedPrekeySignature: key32() });
    expect(UserBundleSchema.safeParse(b).success).toBe(false);
  });

  it('rejects a non-UUID id', () => {
    const b = bundle({ id: 'u1' });
    expect(UserBundleSchema.safeParse(b).success).toBe(false);
  });
});

describe('SEC-20260721-025 — WS schemas match the real wire shape', () => {
  it('accepts a genuine typing event', () => {
    const evt = { type: 'typing', senderId: uuid(), senderUsername: 'alice', isTyping: true };
    expect(WsTypingSchema.safeParse(evt).success).toBe(true);
  });

  it('rejects the old placeholder typing shape (senderId only)', () => {
    expect(WsTypingSchema.safeParse({ type: 'typing', senderId: uuid() }).success).toBe(false);
  });

  it('accepts a genuine read event', () => {
    const evt = { type: 'read', senderId: uuid(), messageIds: [uuid()] };
    expect(WsReadReceiptSchema.safeParse(evt).success).toBe(true);
  });

  it('rejects the old placeholder read shape (read_receipt/readerId)', () => {
    const evt = { type: 'read_receipt', readerId: uuid(), messageIds: [uuid()] };
    expect(WsReadReceiptSchema.safeParse(evt).success).toBe(false);
  });
});
