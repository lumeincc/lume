// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260621-022 — an inbound X3DH must be answered with the signed prekey the
 * sender addressed: the current SPK, or the previous one while still inside its
 * grace window. After grace (or for an unknown SPK) it must fail closed.
 */

import { describe, it, expect } from 'vitest';

import { selectRespondSpk, PREVIOUS_SPK_GRACE_PERIOD_MS } from '@/crypto/spkRotation';
import type { LocalPreKeyMaterial } from '@/crypto/storage';

const cur = { publicKey: 'CUR', secretKey: 's-cur' };
const prev = { publicKey: 'PREV', secretKey: 's-prev' };

function material(extra?: Partial<LocalPreKeyMaterial>): LocalPreKeyMaterial {
  return { signedPreKey: cur, oneTimePreKeys: [], updatedAt: 0, ...extra };
}

describe('selectRespondSpk (SEC-20260621-022)', () => {
  it('uses the current SPK when none is addressed or it matches the current', () => {
    expect(selectRespondSpk(material(), undefined, 1000)).toBe(cur);
    expect(selectRespondSpk(material(), 'CUR', 1000)).toBe(cur);
  });

  it('uses the previous SPK when addressed and within the grace window', () => {
    const m = material({ previousSignedPreKey: prev, previousSpkRetiredAt: 1000 });
    expect(selectRespondSpk(m, 'PREV', 1000 + PREVIOUS_SPK_GRACE_PERIOD_MS - 1)).toBe(prev);
  });

  it('rejects the previous SPK after the grace window expires (fail closed)', () => {
    const m = material({ previousSignedPreKey: prev, previousSpkRetiredAt: 1000 });
    expect(selectRespondSpk(m, 'PREV', 1000 + PREVIOUS_SPK_GRACE_PERIOD_MS + 1)).toBeNull();
  });

  it('rejects an unknown addressed SPK (fail closed)', () => {
    const m = material({ previousSignedPreKey: prev, previousSpkRetiredAt: 1000 });
    expect(selectRespondSpk(m, 'UNKNOWN', 1000)).toBeNull();
  });
});
