// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for crypto/ratchet.ts
 * Covers: X3DH initiation/response, Double Ratchet encrypt/decrypt,
 * serialization/deserialization, out-of-order delivery, forward secrecy.
 */

import { describe, it, expect } from 'vitest';
import {
  x3dhInitiate,
  x3dhRespond,
  initSenderSession,
  initReceiverSession,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeSession,
  deserializeSession,
  type X3DHBundle,
} from '@/crypto/ratchet';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { generateExchangeKeyPair, generateSigningKeyPair, sign } from '@/crypto/keys';
import nacl from 'tweetnacl';
import { decodeBase64, encodeBase64 } from 'tweetnacl-util';

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeSharedSecret(): Uint8Array {
  return nacl.randomBytes(32);
}

function signPreKey(spkPublicKey: string, signingKeyPair: ReturnType<typeof generateSigningKeyPair>): string {
  const spkBytes = decodeBase64(spkPublicKey);
  const sig = sign(spkBytes, signingKeyPair.secretKey);
  return encodeBase64(sig);
}

function makeX3DHParams() {
  const senderIdentityKP = generateExchangeKeyPair();
  const recipientIdentityKP = generateExchangeKeyPair();
  const recipientSignedPreKP = generateExchangeKeyPair();
  const recipientOPK = generateExchangeKeyPair();
  const recipientSigningKP = generateSigningKeyPair();

  const bundle: X3DHBundle = {
    identityKey: recipientIdentityKP.publicKey,
    signingKey: recipientSigningKP.publicKey,
    signedPreKey: recipientSignedPreKP.publicKey,
    signature: signPreKey(recipientSignedPreKP.publicKey, recipientSigningKP),
    oneTimePreKey: recipientOPK.publicKey,
  };

  return { senderIdentityKP, recipientIdentityKP, recipientSignedPreKP, recipientOPK, recipientSigningKP, bundle };
}

// ── X3DH ────────────────────────────────────────────────────────────────────

describe('x3dhInitiate and x3dhRespond', () => {
  it('both sides derive the same shared secret (with OPK)', () => {
    const { senderIdentityKP, recipientIdentityKP, recipientSignedPreKP, recipientOPK, bundle } =
      makeX3DHParams();

    const { sharedSecret: senderSecret, ephemeralPublicKey } = x3dhInitiate(
      senderIdentityKP,
      bundle
    );

    const recipientSecret = x3dhRespond(
      recipientIdentityKP,
      recipientSignedPreKP,
      recipientOPK,
      senderIdentityKP.publicKey,
      ephemeralPublicKey
    );

    expect(Buffer.from(senderSecret).toString('hex')).toBe(
      Buffer.from(recipientSecret).toString('hex')
    );
  });

  it('both sides derive the same shared secret (without OPK)', () => {
    const senderIdentityKP = generateExchangeKeyPair();
    const recipientIdentityKP = generateExchangeKeyPair();
    const recipientSignedPreKP = generateExchangeKeyPair();
    const recipientSigningKP = generateSigningKeyPair();

    const bundle: X3DHBundle = {
      identityKey: recipientIdentityKP.publicKey,
      signingKey: recipientSigningKP.publicKey,
      signedPreKey: recipientSignedPreKP.publicKey,
      signature: signPreKey(recipientSignedPreKP.publicKey, recipientSigningKP),
    };

    const { sharedSecret: senderSecret, ephemeralPublicKey } = x3dhInitiate(
      senderIdentityKP,
      bundle
    );

    const recipientSecret = x3dhRespond(
      recipientIdentityKP,
      recipientSignedPreKP,
      null,
      senderIdentityKP.publicKey,
      ephemeralPublicKey
    );

    expect(Buffer.from(senderSecret).toString('hex')).toBe(
      Buffer.from(recipientSecret).toString('hex')
    );
  });

  it('produces a 32-byte shared secret', () => {
    const senderKP = generateExchangeKeyPair();
    const recipientKP = generateExchangeKeyPair();
    const spKP = generateExchangeKeyPair();
    const sigKP = generateSigningKeyPair();

    const bundle: X3DHBundle = {
      identityKey: recipientKP.publicKey,
      signingKey: sigKP.publicKey,
      signedPreKey: spKP.publicKey,
      signature: signPreKey(spKP.publicKey, sigKP),
    };

    const { sharedSecret } = x3dhInitiate(senderKP, bundle);
    expect(sharedSecret.length).toBe(32);
  });

  it('ephemeralPublicKey is a valid base64 X25519 public key (32 bytes)', () => {
    const senderKP = generateExchangeKeyPair();
    const recipientKP = generateExchangeKeyPair();
    const spKP = generateExchangeKeyPair();
    const sigKP = generateSigningKeyPair();

    const bundle: X3DHBundle = {
      identityKey: recipientKP.publicKey,
      signingKey: sigKP.publicKey,
      signedPreKey: spKP.publicKey,
      signature: signPreKey(spKP.publicKey, sigKP),
    };

    const { ephemeralPublicKey } = x3dhInitiate(senderKP, bundle);
    expect(decodeBase64(ephemeralPublicKey).length).toBe(32);
  });

  it('different X3DH handshakes produce different secrets', () => {
    const sender1 = generateExchangeKeyPair();
    const sender2 = generateExchangeKeyPair();
    const recipientKP = generateExchangeKeyPair();
    const spKP = generateExchangeKeyPair();
    const sigKP = generateSigningKeyPair();

    const bundle: X3DHBundle = {
      identityKey: recipientKP.publicKey,
      signingKey: sigKP.publicKey,
      signedPreKey: spKP.publicKey,
      signature: signPreKey(spKP.publicKey, sigKP),
    };

    const { sharedSecret: s1 } = x3dhInitiate(sender1, bundle);
    const { sharedSecret: s2 } = x3dhInitiate(sender2, bundle);

    expect(Buffer.from(s1).toString('hex')).not.toBe(
      Buffer.from(s2).toString('hex')
    );
  });

  it('rejects a bundle with invalid SPK signature (MITM protection)', () => {
    const senderKP = generateExchangeKeyPair();
    const recipientKP = generateExchangeKeyPair();
    const spKP = generateExchangeKeyPair();
    const sigKP = generateSigningKeyPair();
    const attackerSigKP = generateSigningKeyPair();

    // Подпись сделана другим ключом — имитация MITM
    const bundle: X3DHBundle = {
      identityKey: recipientKP.publicKey,
      signingKey: sigKP.publicKey,
      signedPreKey: spKP.publicKey,
      signature: signPreKey(spKP.publicKey, attackerSigKP),
    };

    expect(() => x3dhInitiate(senderKP, bundle)).toThrow(
      'X3DH: signed prekey signature verification failed'
    );
  });

  it('rejects a bundle with tampered signedPreKey', () => {
    const senderKP = generateExchangeKeyPair();
    const recipientKP = generateExchangeKeyPair();
    const spKP = generateExchangeKeyPair();
    const sigKP = generateSigningKeyPair();

    // Подпись валидна для spKP, но подменяем signedPreKey на другой ключ
    const tamperedSpKP = generateExchangeKeyPair();
    const bundle: X3DHBundle = {
      identityKey: recipientKP.publicKey,
      signingKey: sigKP.publicKey,
      signedPreKey: tamperedSpKP.publicKey,
      signature: signPreKey(spKP.publicKey, sigKP),
    };

    expect(() => x3dhInitiate(senderKP, bundle)).toThrow(
      'X3DH: signed prekey signature verification failed'
    );
  });
});

// ── Double Ratchet: encrypt / decrypt ───────────────────────────────────────

describe('ratchetEncrypt and ratchetDecrypt', () => {
  it('basic round-trip: Alice sends, Bob receives', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();

    const aliceSession = initSenderSession(sharedSecret, bobKP.publicKey);
    const bobSession = initReceiverSession(sharedSecret, bobKP);

    const plaintext = Buffer.from('hello Bob');
    const encrypted = ratchetEncrypt(aliceSession, plaintext);
    const decrypted = ratchetDecrypt(bobSession, encrypted);

    expect(decrypted).not.toBeNull();
    expect(Buffer.from(decrypted!).toString('utf8')).toBe('hello Bob');
  });

  it('multiple sequential messages are all decrypted correctly', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();

    const aliceSession = initSenderSession(sharedSecret, bobKP.publicKey);
    const bobSession = initReceiverSession(sharedSecret, bobKP);

    const messages = ['msg 1', 'msg 2', 'msg 3', 'msg 4', 'msg 5'];
    for (const text of messages) {
      const encrypted = ratchetEncrypt(aliceSession, Buffer.from(text));
      const decrypted = ratchetDecrypt(bobSession, encrypted);
      expect(Buffer.from(decrypted!).toString('utf8')).toBe(text);
    }
  });

  it('increments sendingMessageNumber on each encrypt', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();
    const session = initSenderSession(sharedSecret, bobKP.publicKey);

    expect(session.sendingMessageNumber).toBe(0);
    const e1 = ratchetEncrypt(session, Buffer.from('a'));
    expect(session.sendingMessageNumber).toBe(1);
    expect(e1.header.messageNumber).toBe(0);

    const e2 = ratchetEncrypt(session, Buffer.from('b'));
    expect(session.sendingMessageNumber).toBe(2);
    expect(e2.header.messageNumber).toBe(1);
  });

  it('ciphertext is different for equal plaintexts (unique nonces)', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();
    const session = initSenderSession(sharedSecret, bobKP.publicKey);
    const msg = Buffer.from('same');

    const e1 = ratchetEncrypt(session, msg);
    const e2 = ratchetEncrypt(session, msg);
    expect(e1.ciphertext).not.toBe(e2.ciphertext);
    expect(e1.nonce).not.toBe(e2.nonce);
  });

  it('throws when encrypting without an initialized sending chain', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();
    const session = initReceiverSession(sharedSecret, bobKP);
    // Receiver has no sendingChainKey yet
    expect(() =>
      ratchetEncrypt(session, Buffer.from('fail'))
    ).toThrow('Sending chain not initialized');
  });

  it('returns null for tampered ciphertext', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();

    const aliceSession = initSenderSession(sharedSecret, bobKP.publicKey);
    const bobSession = initReceiverSession(sharedSecret, bobKP);

    const encrypted = ratchetEncrypt(aliceSession, Buffer.from('tamper me'));
    // Decode ciphertext, flip one byte, re-encode — keeps valid base64
    const raw = decodeBase64(encrypted.ciphertext);
    raw[0] = raw[0]! ^ 0xff;  // flip all bits in first byte
    const tampered = { ...encrypted, ciphertext: encodeBase64(raw) };

    const result = ratchetDecrypt(bobSession, tampered);
    expect(result).toBeNull();
  });
});

// ── Header authentication & decrypt rollback (SEC-20260621-018) ──────────────

describe('header authentication & decrypt rollback (SEC-20260621-018)', () => {
  function setup() {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();
    return {
      aliceSession: initSenderSession(sharedSecret, bobKP.publicKey),
      bobSession: initReceiverSession(sharedSecret, bobKP),
    };
  }

  function snapshotState(s: ReturnType<typeof initReceiverSession>) {
    return {
      receivingMessageNumber: s.receivingMessageNumber,
      receivingChainKey: s.receivingChainKey
        ? Buffer.from(s.receivingChainKey).toString('hex')
        : null,
      rootKey: Buffer.from(s.rootKey).toString('hex'),
      dhReceivingPublicKey: s.dhReceivingPublicKey,
      skippedSize: s.skippedMessageKeys.size,
    };
  }

  it('rejects a tampered previousChainLength and leaves the session unchanged', () => {
    const { aliceSession, bobSession } = setup();
    const enc = ratchetEncrypt(aliceSession, Buffer.from('hi'));
    const before = snapshotState(bobSession);
    const tampered = {
      ...enc,
      header: { ...enc.header, previousChainLength: enc.header.previousChainLength + 5 },
    };
    expect(ratchetDecrypt(bobSession, tampered)).toBeNull();
    expect(snapshotState(bobSession)).toEqual(before);
  });

  it('rejects a tampered messageNumber and leaves the session unchanged', () => {
    const { aliceSession, bobSession } = setup();
    const enc = ratchetEncrypt(aliceSession, Buffer.from('hi'));
    const before = snapshotState(bobSession);
    const tampered = {
      ...enc,
      header: { ...enc.header, messageNumber: enc.header.messageNumber + 3 },
    };
    expect(ratchetDecrypt(bobSession, tampered)).toBeNull();
    expect(snapshotState(bobSession)).toEqual(before);
  });

  it('rejects a tampered nonce and leaves the session unchanged', () => {
    const { aliceSession, bobSession } = setup();
    const enc = ratchetEncrypt(aliceSession, Buffer.from('hi'));
    const before = snapshotState(bobSession);
    const raw = decodeBase64(enc.nonce);
    raw[0] = raw[0]! ^ 0xff;
    expect(ratchetDecrypt(bobSession, { ...enc, nonce: encodeBase64(raw) })).toBeNull();
    expect(snapshotState(bobSession)).toEqual(before);
  });

  it('tampered skipped-key ciphertext fails without consuming the cached key', () => {
    const { aliceSession, bobSession } = setup();
    const e0 = ratchetEncrypt(aliceSession, Buffer.from('m0'));
    const e1 = ratchetEncrypt(aliceSession, Buffer.from('m1'));

    // Receive e1 first → e0's key is cached as a skipped key.
    expect(ratchetDecrypt(bobSession, e1)).not.toBeNull();
    const cachedSize = bobSession.skippedMessageKeys.size;
    expect(cachedSize).toBeGreaterThan(0);

    // Tampered e0 must fail and must NOT drop the cached skipped key.
    const raw = decodeBase64(e0.ciphertext);
    raw[0] = raw[0]! ^ 0xff;
    expect(ratchetDecrypt(bobSession, { ...e0, ciphertext: encodeBase64(raw) })).toBeNull();
    expect(bobSession.skippedMessageKeys.size).toBe(cachedSize);

    // The genuine e0 still decrypts — the key was preserved.
    expect(Buffer.from(ratchetDecrypt(bobSession, e0)!).toString('utf8')).toBe('m0');
  });
});

// ── Forward secrecy: old message keys are discarded ─────────────────────────

describe('forward secrecy', () => {
  it('old messages cannot be decrypted after ratchet advances', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();

    const aliceSession = initSenderSession(sharedSecret, bobKP.publicKey);
    const bobSession = initReceiverSession(sharedSecret, bobKP);

    // Message 0
    const e0 = ratchetEncrypt(aliceSession, Buffer.from('first'));
    // Message 1
    const e1 = ratchetEncrypt(aliceSession, Buffer.from('second'));

    // Bob decrypts both (ratchet advances)
    ratchetDecrypt(bobSession, e0);
    ratchetDecrypt(bobSession, e1);

    // Re-decrypting an already-consumed message with the same session
    // returns null because the key was discarded
    const replay = ratchetDecrypt(bobSession, e0);
    expect(replay).toBeNull();
  });
});

// ── Out-of-order delivery ────────────────────────────────────────────────────

describe('out-of-order message delivery', () => {
  it('decrypts out-of-order messages using skipped key cache', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();

    const aliceSession = initSenderSession(sharedSecret, bobKP.publicKey);
    const bobSession = initReceiverSession(sharedSecret, bobKP);

    const e0 = ratchetEncrypt(aliceSession, Buffer.from('msg-0'));
    const e1 = ratchetEncrypt(aliceSession, Buffer.from('msg-1'));
    const e2 = ratchetEncrypt(aliceSession, Buffer.from('msg-2'));

    // Receive out-of-order: 2, 1, 0
    const d2 = ratchetDecrypt(bobSession, e2);
    expect(Buffer.from(d2!).toString('utf8')).toBe('msg-2');

    const d1 = ratchetDecrypt(bobSession, e1);
    expect(Buffer.from(d1!).toString('utf8')).toBe('msg-1');

    const d0 = ratchetDecrypt(bobSession, e0);
    expect(Buffer.from(d0!).toString('utf8')).toBe('msg-0');
  });
});

// ── Serialization ────────────────────────────────────────────────────────────

describe('serializeSession / deserializeSession', () => {
  it('round-trips a sender session without data loss', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();
    const session = initSenderSession(sharedSecret, bobKP.publicKey);

    const serialized = serializeSession(session);
    const restored = deserializeSession(serialized);

    expect(restored.sendingMessageNumber).toBe(session.sendingMessageNumber);
    expect(restored.receivingMessageNumber).toBe(session.receivingMessageNumber);
    expect(restored.dhReceivingPublicKey).toBe(session.dhReceivingPublicKey);
    expect(Buffer.from(restored.rootKey).toString('hex')).toBe(
      Buffer.from(session.rootKey).toString('hex')
    );
  });

  it('restored session can encrypt/decrypt correctly', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();

    const aliceSession = initSenderSession(sharedSecret, bobKP.publicKey);
    const bobSession = initReceiverSession(sharedSecret, bobKP);

    // Alice sends message 0
    const e0 = ratchetEncrypt(aliceSession, Buffer.from('pre-restore'));
    ratchetDecrypt(bobSession, e0);

    // Serialize and restore Alice's session
    const restored = deserializeSession(serializeSession(aliceSession));

    // Alice sends another message from restored session
    const e1 = ratchetEncrypt(restored, Buffer.from('post-restore'));
    const d1 = ratchetDecrypt(bobSession, e1);
    expect(Buffer.from(d1!).toString('utf8')).toBe('post-restore');
  });

  it('serialized session contains no raw Uint8Array fields (JSON-safe)', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();
    const session = initSenderSession(sharedSecret, bobKP.publicKey);

    const serialized = serializeSession(session);
    // Must be JSON-serializable without throwing
    const json = JSON.stringify(serialized);
    expect(typeof json).toBe('string');
    // All binary fields should be strings, not objects
    expect(typeof serialized.rootKey).toBe('string');
  });

  it('deserializes skippedMessageKeys correctly', () => {
    const sharedSecret = makeSharedSecret();
    const bobKP = generateExchangeKeyPair();

    const aliceSession = initSenderSession(sharedSecret, bobKP.publicKey);
    const bobSession = initReceiverSession(sharedSecret, bobKP);

    const e0 = ratchetEncrypt(aliceSession, Buffer.from('msg0'));
    const e1 = ratchetEncrypt(aliceSession, Buffer.from('msg1'));

    // Bob receives e1 first, skipping e0 — key should be cached
    ratchetDecrypt(bobSession, e1);

    const restored = deserializeSession(serializeSession(bobSession));
    expect(restored.skippedMessageKeys).toBeInstanceOf(Map);
    // e0's key should still be in the cache
    expect(restored.skippedMessageKeys.size).toBeGreaterThan(0);

    // Should still be able to decrypt e0 after restore
    const d0 = ratchetDecrypt(restored, e0);
    expect(Buffer.from(d0!).toString('utf8')).toBe('msg0');
  });
});

// ── HKDF (RFC 5869) primitives ──────────────────────────────────────────────

describe('HMAC-SHA-256 (@noble/hashes)', () => {
  it('produces a 32-byte output', () => {
    const key = nacl.randomBytes(32);
    const data = nacl.randomBytes(64);
    const result = hmac(sha256, key, data);
    expect(result.length).toBe(32);
  });

  it('is deterministic (same inputs -> same output)', () => {
    const key = nacl.randomBytes(32);
    const data = nacl.randomBytes(16);
    const r1 = hmac(sha256, key, data);
    const r2 = hmac(sha256, key, data);
    expect(Buffer.from(r1).toString('hex')).toBe(Buffer.from(r2).toString('hex'));
  });

  it('different keys produce different outputs', () => {
    const key1 = nacl.randomBytes(32);
    const key2 = nacl.randomBytes(32);
    const data = nacl.randomBytes(16);
    const r1 = hmac(sha256, key1, data);
    const r2 = hmac(sha256, key2, data);
    expect(Buffer.from(r1).toString('hex')).not.toBe(Buffer.from(r2).toString('hex'));
  });

  it('handles keys longer than block size (64 bytes)', () => {
    const longKey = nacl.randomBytes(200);
    const data = nacl.randomBytes(16);
    const result = hmac(sha256, longKey, data);
    expect(result.length).toBe(32);
  });
});

describe('HKDF', () => {
  it('produces output of requested length', () => {
    const ikm = nacl.randomBytes(32);
    const salt = nacl.randomBytes(16);
    const info = new TextEncoder().encode('test');

    expect(hkdf(sha256, ikm, salt, info, 32).length).toBe(32);
    expect(hkdf(sha256, ikm, salt, info, 64).length).toBe(64);
    expect(hkdf(sha256, ikm, salt, info, 48).length).toBe(48);
  });

  it('is deterministic', () => {
    const ikm = nacl.randomBytes(32);
    const salt = nacl.randomBytes(16);
    const info = new TextEncoder().encode('test-determinism');
    const r1 = hkdf(sha256, ikm, salt, info, 32);
    const r2 = hkdf(sha256, ikm, salt, info, 32);
    expect(Buffer.from(r1).toString('hex')).toBe(Buffer.from(r2).toString('hex'));
  });

  it('different info strings produce different outputs (domain separation)', () => {
    const ikm = nacl.randomBytes(32);
    const salt = nacl.randomBytes(16);
    const info1 = new TextEncoder().encode('context-A');
    const info2 = new TextEncoder().encode('context-B');
    const r1 = hkdf(sha256, ikm, salt, info1, 32);
    const r2 = hkdf(sha256, ikm, salt, info2, 32);
    expect(Buffer.from(r1).toString('hex')).not.toBe(Buffer.from(r2).toString('hex'));
  });

  it('different salts produce different outputs', () => {
    const ikm = nacl.randomBytes(32);
    const salt1 = nacl.randomBytes(16);
    const salt2 = nacl.randomBytes(16);
    const info = new TextEncoder().encode('test');
    const r1 = hkdf(sha256, ikm, salt1, info, 32);
    const r2 = hkdf(sha256, ikm, salt2, info, 32);
    expect(Buffer.from(r1).toString('hex')).not.toBe(Buffer.from(r2).toString('hex'));
  });

  it('works with empty salt (uses zero-filled default per RFC 5869)', () => {
    const ikm = nacl.randomBytes(32);
    const info = new TextEncoder().encode('empty-salt');
    const result = hkdf(sha256, ikm, new Uint8Array(0), info, 32);
    expect(result.length).toBe(32);
  });

  it('works with empty info', () => {
    const ikm = nacl.randomBytes(32);
    const salt = nacl.randomBytes(16);
    const result = hkdf(sha256, ikm, salt, new Uint8Array(0), 32);
    expect(result.length).toBe(32);
  });

  it('longer output (multi-block expand) works correctly', () => {
    const ikm = nacl.randomBytes(32);
    const salt = nacl.randomBytes(16);
    const info = new TextEncoder().encode('multi-block');
    // 128 bytes = 2 SHA-512 blocks
    const result = hkdf(sha256, ikm, salt, info, 128);
    expect(result.length).toBe(128);
    // First 64 bytes should differ from second 64 bytes
    const first = Buffer.from(result.slice(0, 64)).toString('hex');
    const second = Buffer.from(result.slice(64, 128)).toString('hex');
    expect(first).not.toBe(second);
  });
});
