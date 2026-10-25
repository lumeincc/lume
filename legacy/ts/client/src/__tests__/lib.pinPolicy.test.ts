// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-020 — the unlock secret must be at least 8 characters and may be
 * alphanumeric, lifting entropy well past the old 4–6 digit PIN.
 */

import { describe, it, expect } from 'vitest';

import { MIN_PIN_LENGTH, MAX_PIN_LENGTH, isPinLongEnough } from '@/lib/pinPolicy';

describe('pinPolicy', () => {
  it('sets the minimum length to 8', () => {
    expect(MIN_PIN_LENGTH).toBe(8);
    expect(MAX_PIN_LENGTH).toBeGreaterThanOrEqual(64);
  });

  it('rejects secrets shorter than the minimum', () => {
    expect(isPinLongEnough('')).toBe(false);
    expect(isPinLongEnough('1234')).toBe(false); // the old 4-digit floor
    expect(isPinLongEnough('1234567')).toBe(false);
  });

  it('accepts an 8+ character passphrase, numeric or alphanumeric', () => {
    expect(isPinLongEnough('12345678')).toBe(true);
    expect(isPinLongEnough('correct-horse')).toBe(true);
    expect(isPinLongEnough('p@ssphrase99')).toBe(true);
  });
});
