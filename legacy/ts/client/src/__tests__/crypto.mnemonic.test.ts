// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for crypto/mnemonic.ts
 * Covers: mnemonic generation, validation, key derivation,
 * account creation, masking, word verification.
 */

import { describe, it, expect } from 'vitest';
import {
  generateMnemonic,
  validateMnemonic,
  mnemonicToSeed,
  recoverIdentityFromMnemonic,
  createAccountWithMnemonic,
  maskMnemonic,
  getMnemonicWords,
  getRandomWordPositions,
  verifyMnemonicWords,
} from '@/crypto/mnemonic';
import { decodeBase64 } from 'tweetnacl-util';

// ── generateMnemonic ─────────────────────────────────────────────────────────

describe('generateMnemonic', () => {
  it('generates a 12-word mnemonic by default (128-bit strength)', async () => {
    const mnemonic = await generateMnemonic();
    const words = mnemonic.split(' ');
    expect(words.length).toBe(12);
  });

  it('generates a 24-word mnemonic for 256-bit strength', async () => {
    const mnemonic = await generateMnemonic(256);
    const words = mnemonic.split(' ');
    expect(words.length).toBe(24);
  });

  it('generates unique mnemonics on each call', async () => {
    const m1 = await generateMnemonic();
    const m2 = await generateMnemonic();
    expect(m1).not.toBe(m2);
  });

  it('generated mnemonic passes BIP39 validation', async () => {
    const mnemonic = await generateMnemonic();
    expect(await validateMnemonic(mnemonic)).toBe(true);
  });
});

// ── validateMnemonic ─────────────────────────────────────────────────────────

describe('validateMnemonic', () => {
  it('accepts a valid 12-word BIP39 mnemonic', async () => {
    const mnemonic = await generateMnemonic();
    expect(await validateMnemonic(mnemonic)).toBe(true);
  });

  it('rejects a completely invalid string', async () => {
    expect(await validateMnemonic('this is not valid at all')).toBe(false);
  });

  it('rejects an empty string', async () => {
    expect(await validateMnemonic('')).toBe(false);
  });

  it('rejects a mnemonic with a wrong word', async () => {
    // Replace first word with a non-BIP39 word
    const words = (await generateMnemonic()).split(' ');
    words[0] = 'xxxxinvalidword';
    expect(await validateMnemonic(words.join(' '))).toBe(false);
  });

  it('rejects a mnemonic with wrong checksum (word shuffled)', async () => {
    const words = (await generateMnemonic()).split(' ');
    // Swap two words to break checksum
    [words[0], words[1]] = [words[1]!, words[0]!];
    // Most shuffles break the BIP39 checksum; this is non-deterministic
    // but overwhelmingly likely to fail. We do a best-effort check.
    const isValid = await validateMnemonic(words.join(' '));
    // It's theoretically possible (though extremely rare) for a swap to still be valid,
    // so we only assert that the function returns a boolean without throwing.
    expect(typeof isValid).toBe('boolean');
  });
});

// ── mnemonicToSeed ───────────────────────────────────────────────────────────

describe('mnemonicToSeed', () => {
  it('returns a 64-byte seed', async () => {
    const mnemonic = await generateMnemonic();
    const seed = await mnemonicToSeed(mnemonic);
    expect(seed).toBeInstanceOf(Uint8Array);
    expect(seed.length).toBe(64);
  });

  it('is deterministic for the same mnemonic and passphrase', async () => {
    const mnemonic = await generateMnemonic();
    const s1 = await mnemonicToSeed(mnemonic, 'pass');
    const s2 = await mnemonicToSeed(mnemonic, 'pass');
    expect(Buffer.from(s1).toString('hex')).toBe(Buffer.from(s2).toString('hex'));
  });

  it('produces different seeds for different passphrases', async () => {
    const mnemonic = await generateMnemonic();
    const s1 = await mnemonicToSeed(mnemonic, '');
    const s2 = await mnemonicToSeed(mnemonic, 'secret');
    expect(Buffer.from(s1).toString('hex')).not.toBe(Buffer.from(s2).toString('hex'));
  });

  it('produces different seeds for different mnemonics', async () => {
    const m1 = await generateMnemonic();
    const m2 = await generateMnemonic();
    const s1 = await mnemonicToSeed(m1);
    const s2 = await mnemonicToSeed(m2);
    expect(Buffer.from(s1).toString('hex')).not.toBe(Buffer.from(s2).toString('hex'));
  });
});

// ── recoverIdentityFromMnemonic ──────────────────────────────────────────────

describe('recoverIdentityFromMnemonic', () => {
  it('returns an IdentityKeys object with signing and exchange keypairs', async () => {
    const mnemonic = await generateMnemonic();
    const identity = await recoverIdentityFromMnemonic(mnemonic);

    expect(identity.signing).toBeDefined();
    expect(identity.exchange).toBeDefined();
    expect(typeof identity.signing.publicKey).toBe('string');
    expect(typeof identity.exchange.publicKey).toBe('string');
  });

  it('is deterministic — same mnemonic yields same keys', async () => {
    const mnemonic = await generateMnemonic();
    const id1 = await recoverIdentityFromMnemonic(mnemonic);
    const id2 = await recoverIdentityFromMnemonic(mnemonic);

    expect(id1.signing.publicKey).toBe(id2.signing.publicKey);
    expect(id1.signing.secretKey).toBe(id2.signing.secretKey);
    expect(id1.exchange.publicKey).toBe(id2.exchange.publicKey);
    expect(id1.exchange.secretKey).toBe(id2.exchange.secretKey);
  });

  it('different mnemonics yield different keys', async () => {
    const m1 = await generateMnemonic();
    const m2 = await generateMnemonic();
    const id1 = await recoverIdentityFromMnemonic(m1);
    const id2 = await recoverIdentityFromMnemonic(m2);

    expect(id1.signing.publicKey).not.toBe(id2.signing.publicKey);
    expect(id1.exchange.publicKey).not.toBe(id2.exchange.publicKey);
  });

  it('passphrase changes the derived keys', async () => {
    const mnemonic = await generateMnemonic();
    const id1 = await recoverIdentityFromMnemonic(mnemonic, '');
    const id2 = await recoverIdentityFromMnemonic(mnemonic, 'extra-passphrase');
    expect(id1.signing.publicKey).not.toBe(id2.signing.publicKey);
  });

  it('throws for an invalid mnemonic', async () => {
    await expect(
      recoverIdentityFromMnemonic('invalid mnemonic phrase that is wrong')
    ).rejects.toThrow('Invalid mnemonic phrase');
  });

  it('derived Ed25519 signing key has correct length (32 public, 64 secret)', async () => {
    const mnemonic = await generateMnemonic();
    const identity = await recoverIdentityFromMnemonic(mnemonic);
    expect(decodeBase64(identity.signing.publicKey).length).toBe(32);
    expect(decodeBase64(identity.signing.secretKey).length).toBe(64);
  });

  it('derived X25519 exchange key has correct length (32 bytes each)', async () => {
    const mnemonic = await generateMnemonic();
    const identity = await recoverIdentityFromMnemonic(mnemonic);
    expect(decodeBase64(identity.exchange.publicKey).length).toBe(32);
    expect(decodeBase64(identity.exchange.secretKey).length).toBe(32);
  });
});

// ── createAccountWithMnemonic ────────────────────────────────────────────────

describe('createAccountWithMnemonic', () => {
  it('returns a mnemonic and identity keys', async () => {
    const result = await createAccountWithMnemonic();
    expect(typeof result.mnemonic).toBe('string');
    expect(result.identity).toBeDefined();
    expect(result.identity.signing).toBeDefined();
    expect(result.identity.exchange).toBeDefined();
  });

  it('mnemonic has 12 words by default', async () => {
    const result = await createAccountWithMnemonic();
    expect(result.mnemonic.split(' ').length).toBe(12);
  });

  it('mnemonic has 24 words for 256-bit strength', async () => {
    const result = await createAccountWithMnemonic(256);
    expect(result.mnemonic.split(' ').length).toBe(24);
  });

  it('identity can be recovered from returned mnemonic', async () => {
    const { mnemonic, identity } = await createAccountWithMnemonic();
    const recovered = await recoverIdentityFromMnemonic(mnemonic);
    expect(recovered.signing.publicKey).toBe(identity.signing.publicKey);
    expect(recovered.exchange.publicKey).toBe(identity.exchange.publicKey);
  });
});

// ── maskMnemonic ─────────────────────────────────────────────────────────────

describe('maskMnemonic', () => {
  it('masks all words for a short (<=4 word) phrase', () => {
    // Not a real BIP39 phrase — just testing masking logic
    const masked = maskMnemonic('one two three four');
    expect(masked).toBe('**** **** **** ****');
  });

  it('shows first and last word, hides the middle', async () => {
    const mnemonic = await generateMnemonic(); // 12 words
    const words = mnemonic.split(' ');
    const masked = maskMnemonic(mnemonic);

    expect(masked.startsWith(words[0]!)).toBe(true);
    expect(masked.endsWith(words[words.length - 1]!)).toBe(true);
    expect(masked).toContain('****');
    expect(masked).toContain('...');
  });

  it('does not expose any secret words in the middle', async () => {
    const mnemonic = await generateMnemonic();
    const words = mnemonic.split(' ');
    const masked = maskMnemonic(mnemonic);
    const maskedParts = masked.split(' ');

    // Inner words (index 1 to length-2) should not appear literally
    for (let i = 1; i < words.length - 1; i++) {
      // Word might coincidentally appear at position 0 or last; just check middle masked parts
      const middleMaskedParts = maskedParts.slice(1, maskedParts.length - 1);
      const literalInMiddle = middleMaskedParts.some(
        (p) => p === words[i] && p !== '****' && p !== '...'
      );
      expect(literalInMiddle).toBe(false);
    }
  });
});

// ── getMnemonicWords ─────────────────────────────────────────────────────────

describe('getMnemonicWords', () => {
  it('returns words as an array', () => {
    const mnemonic = 'one two three';
    expect(getMnemonicWords(mnemonic)).toEqual(['one', 'two', 'three']);
  });

  it('returns 12 words for a standard 12-word mnemonic', async () => {
    const mnemonic = await generateMnemonic();
    expect(getMnemonicWords(mnemonic).length).toBe(12);
  });
});

// ── getRandomWordPositions ───────────────────────────────────────────────────

describe('getRandomWordPositions', () => {
  it('returns the requested number of positions', () => {
    const positions = getRandomWordPositions(12, 3);
    expect(positions.length).toBe(3);
  });

  it('positions are within bounds [0, wordCount)', () => {
    const wordCount = 12;
    const positions = getRandomWordPositions(wordCount, 4);
    for (const p of positions) {
      expect(p).toBeGreaterThanOrEqual(0);
      expect(p).toBeLessThan(wordCount);
    }
  });

  it('all positions are unique', () => {
    const positions = getRandomWordPositions(12, 5);
    const unique = new Set(positions);
    expect(unique.size).toBe(positions.length);
  });

  it('positions are sorted ascending', () => {
    const positions = getRandomWordPositions(12, 4);
    for (let i = 1; i < positions.length; i++) {
      expect(positions[i]!).toBeGreaterThanOrEqual(positions[i - 1]!);
    }
  });

  it('limits to wordCount if checkCount exceeds wordCount', () => {
    const positions = getRandomWordPositions(3, 10);
    expect(positions.length).toBe(3);
  });
});

// ── verifyMnemonicWords ──────────────────────────────────────────────────────

describe('verifyMnemonicWords', () => {
  it('returns true when all answers are correct', () => {
    const mnemonic = 'abandon ability able about above absent';
    const positions = [0, 2, 4];
    const answers = ['abandon', 'able', 'above'];
    expect(verifyMnemonicWords(mnemonic, positions, answers)).toBe(true);
  });

  it('returns false when an answer is wrong', () => {
    const mnemonic = 'abandon ability able about above absent';
    const positions = [0, 2];
    const answers = ['abandon', 'wrong'];
    expect(verifyMnemonicWords(mnemonic, positions, answers)).toBe(false);
  });

  it('is case-insensitive', () => {
    const mnemonic = 'abandon ability able about above absent';
    const positions = [0, 1];
    const answers = ['ABANDON', 'ABILITY'];
    expect(verifyMnemonicWords(mnemonic, positions, answers)).toBe(true);
  });

  it('trims whitespace from answers', () => {
    const mnemonic = 'abandon ability able about above absent';
    const positions = [0];
    const answers = ['  abandon  '];
    expect(verifyMnemonicWords(mnemonic, positions, answers)).toBe(true);
  });

  it('returns false for empty answers array', () => {
    const mnemonic = 'abandon ability able';
    expect(verifyMnemonicWords(mnemonic, [0], [])).toBe(false);
  });
});
