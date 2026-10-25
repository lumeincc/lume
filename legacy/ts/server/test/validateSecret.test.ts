// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, it, expect } from 'vitest';
import crypto from 'crypto';

import { validateWsJwtSecret } from '../src/utils/validateSecret';

describe('validateWsJwtSecret (SEC-20260621-014)', () => {
  it('rejects a missing secret', () => {
    expect(validateWsJwtSecret(undefined).ok).toBe(false);
    expect(validateWsJwtSecret(null).ok).toBe(false);
    expect(validateWsJwtSecret('').ok).toBe(false);
  });

  it('rejects a too-short secret', () => {
    expect(validateWsJwtSecret('short-secret').ok).toBe(false);
  });

  it('rejects the documented example placeholder', () => {
    expect(
      validateWsJwtSecret('CHANGE_ME_TO_A_LONG_RANDOM_SECRET_AT_LEAST_32_BYTES').ok,
    ).toBe(false);
  });

  it('rejects low-entropy repeated strings', () => {
    expect(validateWsJwtSecret('x'.repeat(40)).ok).toBe(false);
    expect(validateWsJwtSecret('ab'.repeat(20)).ok).toBe(false);
  });

  it('accepts a generated 32+ byte random secret', () => {
    expect(validateWsJwtSecret(crypto.randomBytes(32).toString('hex'))).toEqual({ ok: true });
    expect(validateWsJwtSecret(crypto.randomBytes(48).toString('base64'))).toEqual({ ok: true });
  });
});
