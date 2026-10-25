// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260721-007 — JSON_LIMIT must be validated at startup.
 *
 * The advisory's precondition is a limit value the parser cannot read: before
 * body-parser 1.20.6 that silently removed the body size ceiling rather than
 * erroring. The dependency is now past it, so these tests pin the second half of
 * the required validation — that an unreadable value stops the boot instead of
 * being trusted, so the pattern is not waiting for the next dependency.
 */

import { describe, it, expect } from 'vitest';

import { validateJsonLimit } from '../src/utils/validateJsonLimit';

describe('validateJsonLimit', () => {
  it('accepts the forms bytes understands', () => {
    for (const value of ['8mb', '512kb', '1048576', '2.5mb', '100b']) {
      const result = validateJsonLimit(value);
      expect(result.ok, `${value} should be accepted`).toBe(true);
    }
  });

  it('is case- and whitespace-tolerant, and normalises what it returns', () => {
    expect(validateJsonLimit('8MB')).toEqual({ ok: true, value: '8MB' });
    // Outer spaces are harmless to us and are worse than a rejection in bytes:
    // ' 8mb ' parses there as 8 *bytes*. Trimmed rather than passed through.
    expect(validateJsonLimit(' 8mb ')).toEqual({ ok: true, value: '8mb' });
  });

  it('falls back when unset — the variable is optional', () => {
    expect(validateJsonLimit(undefined)).toEqual({ ok: true, value: '8mb' });
    expect(validateJsonLimit(null)).toEqual({ ok: true, value: '8mb' });
    expect(validateJsonLimit(undefined, '4mb')).toEqual({ ok: true, value: '4mb' });
  });

  it('is stricter than bytes.parse where bytes fails silently', () => {
    // Checked against the real parser rather than assumed. bytes.parse is more
    // permissive than the advisory implies, and worse: it does not only return
    // null. Some inputs parse to a tiny number instead —
    //
    //   bytes.parse('8 mb')  -> 8388608   (interior space is fine)
    //   bytes.parse(' 8mb ') -> 8         (outer spaces: EIGHT BYTES)
    //   bytes.parse('8mib')  -> 8         (wrong unit: EIGHT BYTES)
    //
    // A limit of 8 bytes rejects every real request, so the silent-misparse
    // surface is wider than "limit disabled". We trim the first and refuse the
    // second rather than passing either through.
    expect(validateJsonLimit('8 mb').ok).toBe(true);
    expect(validateJsonLimit(' 8mb ')).toEqual({ ok: true, value: '8mb' });
    expect(validateJsonLimit('8mib').ok).toBe(false);
  });

  it('rejects values bytes cannot parse', () => {
    for (const value of ['eight megabytes', '8mib', 'mb', '8mb!', '-1', 'NaN', '8 m b']) {
      const result = validateJsonLimit(value);
      expect(result.ok, `${value} should be rejected`).toBe(false);
    }
  });

  it('rejects set-but-empty — someone set it and got it wrong', () => {
    expect(validateJsonLimit('').ok).toBe(false);
    expect(validateJsonLimit('   ').ok).toBe(false);
  });

  it('rejects a non-positive size', () => {
    expect(validateJsonLimit('0').ok).toBe(false);
    expect(validateJsonLimit('0mb').ok).toBe(false);
  });

  it('rejects a size too large to be deliberate', () => {
    // `verify` copies every accepted body into rawBody, so the real cost is
    // roughly double whatever is allowed here.
    const result = validateJsonLimit('2gb');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('ceiling');
  });

  it('gives a reason naming the offending value, so the log is actionable', () => {
    const result = validateJsonLimit('eight megabytes');
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain('eight megabytes');
  });
});
