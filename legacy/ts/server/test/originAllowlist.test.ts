// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, expect, it } from 'vitest';
import { buildOriginAllowlist, isOriginAllowed } from '../src/utils/originAllowlist';

describe('origin allowlist', () => {
  it('normalizes origins and hosts', () => {
    const allowlist = buildOriginAllowlist('https://lume.app,app.lume.app');
    expect(allowlist.allowedOrigins.has('https://lume.app')).toBe(true);
    expect(allowlist.allowedHosts.has('app.lume.app')).toBe(true);
  });

  it('blocks disallowed origins', () => {
    const allowlist = buildOriginAllowlist('https://lume.app');
    expect(isOriginAllowed('https://evil.com', allowlist)).toBe(false);
  });

  it('allows subdomains when host matches', () => {
    const allowlist = buildOriginAllowlist('lume.app');
    expect(isOriginAllowed('https://sub.lume.app', allowlist)).toBe(false);
  });

  it('rejects scheme downgrade for schemeful entries (SEC-20260621-012)', () => {
    const allowlist = buildOriginAllowlist('https://lume.app');
    expect(isOriginAllowed('https://lume.app', allowlist)).toBe(true);
    expect(isOriginAllowed('http://lume.app', allowlist)).toBe(false);
  });

  it('allows any scheme only for explicit bare-host config', () => {
    const allowlist = buildOriginAllowlist('lume.app');
    expect(isOriginAllowed('https://lume.app', allowlist)).toBe(true);
    expect(isOriginAllowed('http://lume.app', allowlist)).toBe(true);
  });
});
