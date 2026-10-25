// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Static regression test for SEC-20260621-003.
 * The setup page must NOT hold the recovery mnemonic or the IdentityKeys
 * (which include secret keys) in React state, where they would be exposed via
 * React DevTools / browser state inspection.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../app/setup/page.tsx', import.meta.url), 'utf8');

describe('setup page — no key material in React state (SEC-20260621-003)', () => {
  it('does not hold IdentityKeys in React state', () => {
    expect(src).not.toMatch(/useState<\s*IdentityKeys/);
    expect(src).not.toMatch(/setIdentity\s*\(/);
  });

  it('does not import IdentityKeys for component state', () => {
    expect(src).not.toContain('import type { IdentityKeys }');
  });

  it('holds the recovery mnemonic in a ref, not useState', () => {
    expect(src).not.toMatch(/const \[mnemonic, setMnemonic\]/);
    expect(src).toContain('mnemonicRef');
  });
});
