// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for crypto/keys.ts
 * Covers: key generation, sign/verify, encrypt/decrypt, prekey bundle.
 */

import { describe, it, expect } from 'vitest';
import {
  generateSigningKeyPair,
  generateExchangeKeyPair,
  generateIdentityKeys,
  sign,
  verify,
  encrypt,
  decrypt,
  generatePreKeyBundle,
  randomBytes,
  hash,
} from '@/crypto/keys';
import { decodeBase64 } from 'tweetnacl-util';

// ── Key generation ──────────────────────────────────────────────────────────

describe('generateSigningKeyPair', () => {
  it('returns public and secret keys in base64', () => {
    const kp = generateSigningKeyPair();
    expect(typeof kp.publicKey).toBe('string');
    expect(typeof kp.secretKey).toBe('string');
    expect(kp.publicKey.length).toBeGreaterThan(0);
    expect(kp.secretKey.length).toBeGreaterThan(0);
  });

  it('produces Ed25519 key lengths (32-byte public, 64-byte secret)', () => {
    const kp = generateSigningKeyPair();
    expect(decodeBase64(kp.publicKey).length).toBe(32);
    expect(decodeBase64(kp.secretKey).length).toBe(64);
  });

  it('generates unique keypairs on each call', () => {
    const kp1 = generateSigningKeyPair();
    const kp2 = generateSigningKeyPair();
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
    expect(kp1.secretKey).not.toBe(kp2.secretKey);
  });
});

describe('generateExchangeKeyPair', () => {
  it('returns public and secret keys in base64', () => {
    const kp = generateExchangeKeyPair();
    expect(typeof kp.publicKey).toBe('string');
    expect(typeof kp.secretKey).toBe('string');
  });

  it('produces X25519 key lengths (32-byte each)', () => {
    const kp = generateExchangeKeyPair();
    expect(decodeBase64(kp.publicKey).length).toBe(32);
    expect(decodeBase64(kp.secretKey).length).toBe(32);
  });

  it('generates unique keypairs on each call', () => {
    const kp1 = generateExchangeKeyPair();
    const kp2 = generateExchangeKeyPair();
    expect(kp1.publicKey).not.toBe(kp2.publicKey);
  });
});

describe('generateIdentityKeys', () => {
  it('returns signing and exchange keypairs', () => {
    const identity = generateIdentityKeys();
    expect(identity.signing).toBeDefined();
    expect(identity.exchange).toBeDefined();
    expect(identity.signing.publicKey).not.toBe(identity.exchange.publicKey);
  });

  it('generates unique identities on each call', () => {
    const id1 = generateIdentityKeys();
    const id2 = generateIdentityKeys();
    expect(id1.signing.publicKey).not.toBe(id2.signing.publicKey);
    expect(id1.exchange.publicKey).not.toBe(id2.exchange.publicKey);
  });
});

// ── Sign / Verify ───────────────────────────────────────────────────────────

describe('sign and verify', () => {
  it('produces a valid signature that verifies correctly', () => {
    const kp = generateSigningKeyPair();
    const message = Buffer.from('hello LUME');
    const sig = sign(message, kp.secretKey);
    expect(verify(message, sig, kp.publicKey)).toBe(true);
  });

  it('rejects a tampered message', () => {
    const kp = generateSigningKeyPair();
    const message = Buffer.from('hello LUME');
    const sig = sign(message, kp.secretKey);
    const tampered = Buffer.from('hello LUME!');
    expect(verify(tampered, sig, kp.publicKey)).toBe(false);
  });

  it('rejects a signature from a different key', () => {
    const kp1 = generateSigningKeyPair();
    const kp2 = generateSigningKeyPair();
    const message = Buffer.from('hello');
    const sig = sign(message, kp1.secretKey);
    expect(verify(message, sig, kp2.publicKey)).toBe(false);
  });

  it('produces a 64-byte Ed25519 signature', () => {
    const kp = generateSigningKeyPair();
    const message = Buffer.from('test');
    const sig = sign(message, kp.secretKey);
    expect(sig.length).toBe(64);
  });

  it('signs an empty message correctly', () => {
    const kp = generateSigningKeyPair();
    const message = new Uint8Array(0);
    const sig = sign(message, kp.secretKey);
    expect(verify(message, sig, kp.publicKey)).toBe(true);
  });
});

// ── Encrypt / Decrypt ───────────────────────────────────────────────────────

describe('encrypt and decrypt', () => {
  it('round-trip: decrypted bytes match original plaintext', () => {
    const alice = generateExchangeKeyPair();
    const bob = generateExchangeKeyPair();
    const plaintext = Buffer.from('secret message');

    const { ciphertext, nonce } = encrypt(plaintext, bob.publicKey, alice.secretKey);
    const decrypted = decrypt(ciphertext, nonce, alice.publicKey, bob.secretKey);

    expect(decrypted).not.toBeNull();
    expect(Buffer.from(decrypted!).toString('utf8')).toBe('secret message');
  });

  it('returns null when decrypting with the wrong secret key', () => {
    const alice = generateExchangeKeyPair();
    const bob = generateExchangeKeyPair();
    const mallory = generateExchangeKeyPair();
    const plaintext = Buffer.from('secret');

    const { ciphertext, nonce } = encrypt(plaintext, bob.publicKey, alice.secretKey);
    const result = decrypt(ciphertext, nonce, alice.publicKey, mallory.secretKey);
    expect(result).toBeNull();
  });

  it('uses a unique nonce on every call', () => {
    const alice = generateExchangeKeyPair();
    const bob = generateExchangeKeyPair();
    const msg = Buffer.from('test');

    const r1 = encrypt(msg, bob.publicKey, alice.secretKey);
    const r2 = encrypt(msg, bob.publicKey, alice.secretKey);
    expect(r1.nonce).not.toBe(r2.nonce);
  });

  it('ciphertext differs from plaintext', () => {
    const alice = generateExchangeKeyPair();
    const bob = generateExchangeKeyPair();
    const plaintext = Buffer.from('not encrypted');
    const { ciphertext } = encrypt(plaintext, bob.publicKey, alice.secretKey);
    // Base64-encoded ciphertext should not equal the UTF-8 plaintext
    expect(ciphertext).not.toBe('not encrypted');
  });

  it('returns null when nonce is corrupted', () => {
    const alice = generateExchangeKeyPair();
    const bob = generateExchangeKeyPair();
    const msg = Buffer.from('hello');
    const { ciphertext } = encrypt(msg, bob.publicKey, alice.secretKey);
    // Use a zeroed-out nonce (24 bytes encoded as base64)
    const badNonce = Buffer.from(new Uint8Array(24)).toString('base64');
    const result = decrypt(ciphertext, badNonce, alice.publicKey, bob.secretKey);
    expect(result).toBeNull();
  });

  it('encrypts and decrypts a large payload (1 MB)', () => {
    const alice = generateExchangeKeyPair();
    const bob = generateExchangeKeyPair();
    const large = Buffer.alloc(1024 * 1024);
    for (let i = 0; i < large.length; i++) large[i] = i % 256;

    const { ciphertext, nonce } = encrypt(large, bob.publicKey, alice.secretKey);
    const decrypted = decrypt(ciphertext, nonce, alice.publicKey, bob.secretKey);
    expect(decrypted).not.toBeNull();
    expect(decrypted!.length).toBe(large.length);
    expect(decrypted![0]).toBe(0);
    expect(decrypted![255]).toBe(255);
  });
});

// ── generatePreKeyBundle ────────────────────────────────────────────────────

describe('generatePreKeyBundle', () => {
  it('returns expected fields', () => {
    const exchange = generateExchangeKeyPair();
    const signing = generateSigningKeyPair();
    const bundle = generatePreKeyBundle(exchange, signing, 5);

    expect(bundle.identityKey).toBe(exchange.publicKey);
    expect(bundle.signedPreKey).toBeDefined();
    expect(bundle.signature).toBeDefined();
    expect(Array.isArray(bundle.oneTimePreKeys)).toBe(true);
    expect(bundle.oneTimePreKeys.length).toBe(5);
  });

  it('signature verifies the signedPreKey public key', () => {
    const exchange = generateExchangeKeyPair();
    const signing = generateSigningKeyPair();
    const bundle = generatePreKeyBundle(exchange, signing);

    const sigBytes = decodeBase64(bundle.signature);
    const spkBytes = decodeBase64(bundle.signedPreKey.publicKey);
    expect(verify(spkBytes, sigBytes, signing.publicKey)).toBe(true);
  });

  it('each one-time prekey has unique public key', () => {
    const exchange = generateExchangeKeyPair();
    const signing = generateSigningKeyPair();
    const bundle = generatePreKeyBundle(exchange, signing, 10);

    const pubKeys = bundle.oneTimePreKeys.map((k) => k.publicKey);
    const unique = new Set(pubKeys);
    expect(unique.size).toBe(10);
  });

  it('defaults to 100 one-time prekeys', () => {
    const exchange = generateExchangeKeyPair();
    const signing = generateSigningKeyPair();
    const bundle = generatePreKeyBundle(exchange, signing);
    expect(bundle.oneTimePreKeys.length).toBe(100);
  });
});

// ── Utility functions ───────────────────────────────────────────────────────

describe('randomBytes', () => {
  it('returns a Uint8Array of the requested length', () => {
    const bytes = randomBytes(32);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);
  });

  it('generates different values on each call', () => {
    const a = randomBytes(16);
    const b = randomBytes(16);
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(b).toString('hex'));
  });
});

describe('hash', () => {
  it('returns a 64-byte SHA-512 digest', () => {
    const data = Buffer.from('test');
    const digest = hash(data);
    expect(digest).toBeInstanceOf(Uint8Array);
    expect(digest.length).toBe(64);
  });

  it('is deterministic for the same input', () => {
    const data = Buffer.from('deterministic');
    const h1 = hash(data);
    const h2 = hash(data);
    expect(Buffer.from(h1).toString('hex')).toBe(Buffer.from(h2).toString('hex'));
  });

  it('produces different digests for different inputs', () => {
    const h1 = hash(Buffer.from('foo'));
    const h2 = hash(Buffer.from('bar'));
    expect(Buffer.from(h1).toString('hex')).not.toBe(Buffer.from(h2).toString('hex'));
  });
});
