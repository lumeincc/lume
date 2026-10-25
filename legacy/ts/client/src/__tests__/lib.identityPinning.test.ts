// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for lib/identityPinning.ts — X3DH identity trust-pinning (SEC-20260621-002).
 */

import { describe, it, expect } from 'vitest';
import {
  bundleMatchesTrustedIdentity,
  inboundSenderMatchesTrustedIdentity,
} from '@/lib/identityPinning';

describe('bundleMatchesTrustedIdentity (outbound first-send)', () => {
  const trusted = { publicKey: 'SIGN_TRUSTED', exchangeKey: 'EXCH_TRUSTED' };

  it('accepts a bundle that matches the trusted identity', () => {
    expect(bundleMatchesTrustedIdentity('SIGN_TRUSTED', 'EXCH_TRUSTED', trusted)).toBe(true);
  });

  it('rejects a mismatched signing identity (possible MITM)', () => {
    expect(bundleMatchesTrustedIdentity('SIGN_EVIL', 'EXCH_TRUSTED', trusted)).toBe(false);
  });

  it('rejects a mismatched exchange identity (possible MITM)', () => {
    expect(bundleMatchesTrustedIdentity('SIGN_TRUSTED', 'EXCH_EVIL', trusted)).toBe(false);
  });

  it('trusts on first use when no trusted identity is known', () => {
    expect(bundleMatchesTrustedIdentity('SIGN_ANY', 'EXCH_ANY', null)).toBe(true);
    expect(bundleMatchesTrustedIdentity('SIGN_ANY', 'EXCH_ANY', undefined)).toBe(true);
  });
});

describe('inboundSenderMatchesTrustedIdentity (inbound first X3DH)', () => {
  it('accepts when the sender exchange key matches the trusted contact', () => {
    expect(inboundSenderMatchesTrustedIdentity('EXCH_TRUSTED', { exchangeKey: 'EXCH_TRUSTED' })).toBe(true);
  });

  it('rejects when the sender exchange key differs from the trusted contact', () => {
    expect(inboundSenderMatchesTrustedIdentity('EXCH_EVIL', { exchangeKey: 'EXCH_TRUSTED' })).toBe(false);
  });

  it('trusts on first use when the sender is not yet a known contact', () => {
    expect(inboundSenderMatchesTrustedIdentity('EXCH_ANY', null)).toBe(true);
    expect(inboundSenderMatchesTrustedIdentity('EXCH_ANY', undefined)).toBe(true);
    expect(inboundSenderMatchesTrustedIdentity('EXCH_ANY', {})).toBe(true);
  });
});
