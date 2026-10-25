// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for crypto/safetyNumber.ts
 * Covers: format, determinism, symmetry, sensitivity to input changes.
 */

import { describe, it, expect } from 'vitest';
import { computeSafetyNumber } from '@/crypto/safetyNumber';
import { generateSigningKeyPair, generateExchangeKeyPair } from '@/crypto/keys';

function makeParams() {
  const alice = { signing: generateSigningKeyPair(), exchange: generateExchangeKeyPair() };
  const bob = { signing: generateSigningKeyPair(), exchange: generateExchangeKeyPair() };
  return { alice, bob };
}

// ── Format ───────────────────────────────────────────────────────────────────

describe('computeSafetyNumber — format', () => {
  it('returns a string of 10 groups of 5 digits separated by spaces', () => {
    const { alice, bob } = makeParams();
    const sn = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });

    const groups = sn.split(' ');
    expect(groups.length).toBe(10);
    for (const group of groups) {
      expect(group).toMatch(/^\d{5}$/);
    }
  });

  it('total length is 59 characters (10 * 5 + 9 spaces)', () => {
    const { alice, bob } = makeParams();
    const sn = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });
    expect(sn.length).toBe(59);
  });

  it('each group value is in range [0, 99999]', () => {
    const { alice, bob } = makeParams();
    const sn = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });
    for (const group of sn.split(' ')) {
      const n = parseInt(group, 10);
      expect(n).toBeGreaterThanOrEqual(0);
      expect(n).toBeLessThanOrEqual(99999);
    }
  });
});

// ── Determinism ──────────────────────────────────────────────────────────────

describe('computeSafetyNumber — determinism', () => {
  it('returns the same value for identical inputs', () => {
    const { alice, bob } = makeParams();
    const params = {
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    };
    expect(computeSafetyNumber(params)).toBe(computeSafetyNumber(params));
  });

  it('different key pairs yield different safety numbers', () => {
    const pair1 = makeParams();
    const pair2 = makeParams();

    const sn1 = computeSafetyNumber({
      mySigningPublicKey: pair1.alice.signing.publicKey,
      myExchangeIdentityPublicKey: pair1.alice.exchange.publicKey,
      theirSigningPublicKey: pair1.bob.signing.publicKey,
      theirExchangeIdentityPublicKey: pair1.bob.exchange.publicKey,
    });

    const sn2 = computeSafetyNumber({
      mySigningPublicKey: pair2.alice.signing.publicKey,
      myExchangeIdentityPublicKey: pair2.alice.exchange.publicKey,
      theirSigningPublicKey: pair2.bob.signing.publicKey,
      theirExchangeIdentityPublicKey: pair2.bob.exchange.publicKey,
    });

    expect(sn1).not.toBe(sn2);
  });
});

// ── Symmetry ─────────────────────────────────────────────────────────────────

describe('computeSafetyNumber — symmetry', () => {
  it('Alice sees the same safety number as Bob (symmetric)', () => {
    const { alice, bob } = makeParams();

    const aliceView = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });

    const bobView = computeSafetyNumber({
      mySigningPublicKey: bob.signing.publicKey,
      myExchangeIdentityPublicKey: bob.exchange.publicKey,
      theirSigningPublicKey: alice.signing.publicKey,
      theirExchangeIdentityPublicKey: alice.exchange.publicKey,
    });

    expect(aliceView).toBe(bobView);
  });
});

// ── Sensitivity to input changes ─────────────────────────────────────────────

describe('computeSafetyNumber — sensitivity', () => {
  it('changes when signing public key changes', () => {
    const { alice, bob } = makeParams();
    const other = generateSigningKeyPair();

    const sn1 = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });

    const sn2 = computeSafetyNumber({
      mySigningPublicKey: other.publicKey,  // changed
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });

    expect(sn1).not.toBe(sn2);
  });

  it('changes when exchange public key changes', () => {
    const { alice, bob } = makeParams();
    const other = generateExchangeKeyPair();

    const sn1 = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });

    const sn2 = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: other.publicKey,  // changed
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });

    expect(sn1).not.toBe(sn2);
  });

  it('changes when the other party keys change (MITM detection)', () => {
    const { alice, bob } = makeParams();
    const mitm = makeParams();

    const legitimate = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: bob.signing.publicKey,
      theirExchangeIdentityPublicKey: bob.exchange.publicKey,
    });

    const mitmAttack = computeSafetyNumber({
      mySigningPublicKey: alice.signing.publicKey,
      myExchangeIdentityPublicKey: alice.exchange.publicKey,
      theirSigningPublicKey: mitm.bob.signing.publicKey,
      theirExchangeIdentityPublicKey: mitm.bob.exchange.publicKey,
    });

    expect(legitimate).not.toBe(mitmAttack);
  });
});

// ── Full digit range (SEC-20260721-028) ──────────────────────────────────────

describe('computeSafetyNumber — full digit range', () => {
  it('uses the whole 0–99999 range, producing groups above 65535', () => {
    // V1 read 2 bytes per group (max 65535) with a `% 100000` that never fired,
    // so no group could ever exceed 65535. V2 reads 3 bytes per group, so across
    // a modest sample at least one group lands in 65536–99999. This fails against
    // the old derivation.
    let sawAbove65535 = false;
    for (let i = 0; i < 20 && !sawAbove65535; i++) {
      const { alice, bob } = makeParams();
      const sn = computeSafetyNumber({
        mySigningPublicKey: alice.signing.publicKey,
        myExchangeIdentityPublicKey: alice.exchange.publicKey,
        theirSigningPublicKey: bob.signing.publicKey,
        theirExchangeIdentityPublicKey: bob.exchange.publicKey,
      });
      for (const group of sn.split(' ')) {
        if (parseInt(group, 10) > 65535) {
          sawAbove65535 = true;
          break;
        }
      }
    }
    expect(sawAbove65535).toBe(true);
  });
});
