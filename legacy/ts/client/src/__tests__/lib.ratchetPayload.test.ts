// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for lib/ratchetPayload.ts
 * Covers: encodeRatchetEnvelope structure, parseRatchetEnvelope roundtrip,
 * selfDestruct handling, X3DH init payload, validation of malformed input.
 */

import { describe, it, expect } from 'vitest';
import {
  encodeRatchetEnvelope,
  parseRatchetEnvelope,
  type RatchetEnvelopeV2,
  type X3DHInitPayload,
} from '@/lib/ratchetPayload';
import type { EncryptedMessage, MessageHeader } from '@/crypto/ratchet';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeHeader(overrides?: Partial<MessageHeader>): MessageHeader {
  return {
    publicKey: 'dh_ratchet_pub_key_base64',
    previousChainLength: 0,
    messageNumber: 1,
    ...overrides,
  };
}

function makeEncryptedMessage(overrides?: Partial<EncryptedMessage>): EncryptedMessage {
  return {
    header: makeHeader(),
    ciphertext: 'encrypted_ciphertext_base64',
    nonce: 'nonce_base64_value',
    ...overrides,
  };
}

function makeX3DH(): X3DHInitPayload {
  return {
    senderIdentityKey: 'sender_identity_x25519_base64',
    senderEphemeralKey: 'sender_ephemeral_x25519_base64',
    recipientOneTimePreKey: 'recipient_otpk_base64',
  };
}

// ── encodeRatchetEnvelope ────────────────────────────────────────────────────

describe('encodeRatchetEnvelope', () => {
  it('produces correct JSON structure with v:2 and alg:lume-ratchet', () => {
    const encrypted = makeEncryptedMessage();
    const timestamp = Date.now();

    const payload = encodeRatchetEnvelope({
      encrypted,
      timestamp,
    });

    const parsed = JSON.parse(payload) as RatchetEnvelopeV2;
    expect(parsed.v).toBe(2);
    expect(parsed.alg).toBe('lume-ratchet');
    expect(parsed.header).toEqual(encrypted.header);
    expect(parsed.ciphertext).toBe(encrypted.ciphertext);
    expect(parsed.nonce).toBe(encrypted.nonce);
    expect(parsed.timestamp).toBe(timestamp);
  });

  it('does NOT include selfDestruct in outer envelope', () => {
    const payload = encodeRatchetEnvelope({
      encrypted: makeEncryptedMessage(),
      timestamp: Date.now(),
      selfDestruct: 30,
    });

    const parsed = JSON.parse(payload);
    // selfDestruct should NOT be present on the envelope
    // (it's supposed to be inside the encrypted plaintext)
    // The encodeRatchetEnvelope does NOT put it in the envelope
    expect(parsed.selfDestruct).toBeUndefined();
  });

  it('includes x3dh payload when provided', () => {
    const x3dh = makeX3DH();
    const payload = encodeRatchetEnvelope({
      encrypted: makeEncryptedMessage(),
      timestamp: Date.now(),
      x3dh,
    });

    const parsed = JSON.parse(payload) as RatchetEnvelopeV2;
    expect(parsed.x3dh).toBeDefined();
    expect(parsed.x3dh!.senderIdentityKey).toBe(x3dh.senderIdentityKey);
    expect(parsed.x3dh!.senderEphemeralKey).toBe(x3dh.senderEphemeralKey);
    expect(parsed.x3dh!.recipientOneTimePreKey).toBe(x3dh.recipientOneTimePreKey);
  });

  it('omits x3dh when not provided', () => {
    const payload = encodeRatchetEnvelope({
      encrypted: makeEncryptedMessage(),
      timestamp: Date.now(),
    });

    const parsed = JSON.parse(payload);
    expect(parsed.x3dh).toBeUndefined();
  });
});

// ── parseRatchetEnvelope roundtrip ───────────────────────────────────────────

describe('parseRatchetEnvelope', () => {
  it('roundtrip: encode then parse returns equivalent envelope', () => {
    const encrypted = makeEncryptedMessage({
      header: makeHeader({ messageNumber: 42, previousChainLength: 10 }),
    });
    const timestamp = 1700000000000;

    const payload = encodeRatchetEnvelope({ encrypted, timestamp });
    const parsed = parseRatchetEnvelope(payload);

    expect(parsed).not.toBeNull();
    expect(parsed!.v).toBe(2);
    expect(parsed!.alg).toBe('lume-ratchet');
    expect(parsed!.header.publicKey).toBe(encrypted.header.publicKey);
    expect(parsed!.header.messageNumber).toBe(42);
    expect(parsed!.header.previousChainLength).toBe(10);
    expect(parsed!.ciphertext).toBe(encrypted.ciphertext);
    expect(parsed!.nonce).toBe(encrypted.nonce);
    expect(parsed!.timestamp).toBe(timestamp);
  });

  it('roundtrip with x3dh payload', () => {
    const x3dh = makeX3DH();
    const payload = encodeRatchetEnvelope({
      encrypted: makeEncryptedMessage(),
      timestamp: Date.now(),
      x3dh,
    });

    const parsed = parseRatchetEnvelope(payload);
    expect(parsed).not.toBeNull();
    expect(parsed!.x3dh).toEqual(x3dh);
  });

  it('parses x3dh with null recipientOneTimePreKey', () => {
    const x3dh: X3DHInitPayload = {
      senderIdentityKey: 'key1',
      senderEphemeralKey: 'key2',
      recipientOneTimePreKey: null,
    };

    const envelope: RatchetEnvelopeV2 = {
      v: 2,
      alg: 'lume-ratchet',
      header: makeHeader(),
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
      x3dh,
    };

    const parsed = parseRatchetEnvelope(JSON.stringify(envelope));
    expect(parsed).not.toBeNull();
    expect(parsed!.x3dh!.recipientOneTimePreKey).toBeNull();
  });
});

// ── Backward compatibility: selfDestruct on envelope ─────────────────────────

describe('backward compatibility — selfDestruct on envelope', () => {
  it('parses envelope with selfDestruct field (old format)', () => {
    // Old senders may have selfDestruct on the outer envelope
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      header: makeHeader(),
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
      selfDestruct: 60,
    };

    const parsed = parseRatchetEnvelope(JSON.stringify(envelope));
    expect(parsed).not.toBeNull();
    // The parser should accept it (selfDestruct is optional on the type)
    expect(parsed!.selfDestruct).toBe(60);
  });
});

// ── Invalid input handling ───────────────────────────────────────────────────

describe('invalid input handling', () => {
  it('returns null for empty string', () => {
    expect(parseRatchetEnvelope('')).toBeNull();
  });

  it('returns null for non-JSON', () => {
    expect(parseRatchetEnvelope('not-json-at-all')).toBeNull();
  });

  it('returns null for wrong version', () => {
    const envelope = {
      v: 1,
      alg: 'lume-ratchet',
      header: makeHeader(),
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for legacy v1 nacl-box envelope (SEC-20260621-001)', () => {
    const envelope = {
      v: 1,
      alg: 'nacl-box',
      senderExchangeKey: 'sender_x25519_base64',
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for wrong algorithm', () => {
    const envelope = {
      v: 2,
      alg: 'wrong-alg',
      header: makeHeader(),
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for missing header', () => {
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for missing ciphertext', () => {
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      header: makeHeader(),
      nonce: 'nc',
      timestamp: Date.now(),
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for missing nonce', () => {
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      header: makeHeader(),
      ciphertext: 'ct',
      timestamp: Date.now(),
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for missing timestamp', () => {
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      header: makeHeader(),
      ciphertext: 'ct',
      nonce: 'nc',
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for header with missing publicKey', () => {
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      header: { previousChainLength: 0, messageNumber: 0 },
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for header with wrong types', () => {
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      header: { publicKey: 123, previousChainLength: 'x', messageNumber: 'y' },
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for x3dh with missing senderIdentityKey', () => {
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      header: makeHeader(),
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
      x3dh: { senderEphemeralKey: 'key' },
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for x3dh with non-string recipientOneTimePreKey', () => {
    const envelope = {
      v: 2,
      alg: 'lume-ratchet',
      header: makeHeader(),
      ciphertext: 'ct',
      nonce: 'nc',
      timestamp: Date.now(),
      x3dh: {
        senderIdentityKey: 'key1',
        senderEphemeralKey: 'key2',
        recipientOneTimePreKey: 123,
      },
    };
    expect(parseRatchetEnvelope(JSON.stringify(envelope))).toBeNull();
  });

  it('returns null for non-string input', () => {
    // TypeScript would prevent this, but runtime safety matters
    expect(parseRatchetEnvelope(null as unknown as string)).toBeNull();
    expect(parseRatchetEnvelope(undefined as unknown as string)).toBeNull();
  });
});
