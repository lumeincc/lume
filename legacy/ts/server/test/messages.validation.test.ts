// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-021 predecessor note: these tests used to exercise the
 * hand-rolled `isValidEncryptedPayload` in `routes/messages.ts`. SEC-20260721-024
 * reconciled the two validators — the route now validates through the Zod
 * `EncryptedPayloadSchema` (via `parseEncryptedPayload`), so the tests moved onto
 * the survivor. The first three cases are the original assertions, unchanged in
 * intent; the rest lock in the resource bounds the Zod schema was missing before
 * (bounded `selfDestruct`, base64-and-size-bounded `ciphertext`) so a future
 * "tidy" cannot silently drop them again.
 */

import { describe, expect, it } from 'vitest';
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';

import { parseEncryptedPayload } from '../src/schemas/common';

const key32 = () => encodeBase64(nacl.randomBytes(32));
const nonce24 = () => encodeBase64(nacl.randomBytes(nacl.secretbox.nonceLength));
const cipher = (bytes = 96) => encodeBase64(nacl.randomBytes(bytes));

/** A minimal, valid v2 envelope; overrides are merged in. */
function envelope(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: 2,
    alg: 'lume-ratchet',
    header: { publicKey: key32(), previousChainLength: 0, messageNumber: 1 },
    ciphertext: cipher(),
    nonce: nonce24(),
    timestamp: Date.now(),
    ...overrides,
  });
}

describe('parseEncryptedPayload (reconciled Zod envelope schema)', () => {
  it('rejects legacy nacl-box (v1) envelopes — Double Ratchet (v2) only', () => {
    const payload = JSON.stringify({
      v: 1,
      alg: 'nacl-box',
      senderExchangeKey: key32(),
      ciphertext: encodeBase64(nacl.randomBytes(64)),
      nonce: encodeBase64(nacl.randomBytes(nacl.box.nonceLength)),
      timestamp: Date.now(),
    });

    expect(parseEncryptedPayload(payload)).toBe(false);
  });

  it('accepts a ratchet envelope with an optional X3DH block', () => {
    const key = key32();
    const payload = envelope({
      x3dh: {
        senderIdentityKey: key,
        senderEphemeralKey: key,
        recipientOneTimePreKey: key,
      },
    });

    expect(parseEncryptedPayload(payload)).toBe(true);
  });

  it('rejects malformed payloads', () => {
    expect(parseEncryptedPayload('')).toBe(false);
    expect(parseEncryptedPayload('{}')).toBe(false);
    const badNonce = envelope({ nonce: encodeBase64(nacl.randomBytes(8)) }); // wrong length
    expect(parseEncryptedPayload(badNonce)).toBe(false);
  });

  // --- Resource bounds the hand-rolled validator enforced and the pre-SEC-024
  //     Zod schema did not. Each of these passes the base envelope shape, so a
  //     schema that dropped the bound would accept them.

  it('rejects a self-destruct TTL above the 7-day ceiling', () => {
    expect(parseEncryptedPayload(envelope({ selfDestruct: 7 * 24 * 60 * 60 + 1 }))).toBe(false);
  });

  it('rejects a negative self-destruct TTL', () => {
    expect(parseEncryptedPayload(envelope({ selfDestruct: -1 }))).toBe(false);
  });

  it('accepts a self-destruct TTL within range', () => {
    expect(parseEncryptedPayload(envelope({ selfDestruct: 3600 }))).toBe(true);
    expect(parseEncryptedPayload(envelope({ selfDestruct: null }))).toBe(true);
  });

  it('rejects ciphertext that is not valid base64', () => {
    // Short enough to clear the outer length bound, so only the decoded-base64
    // refine can reject it — which the old `z.string().min(1)` would not have.
    expect(parseEncryptedPayload(envelope({ ciphertext: 'not!valid!base64!!!' }))).toBe(false);
  });
});
