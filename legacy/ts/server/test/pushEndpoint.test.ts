// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, it, expect } from 'vitest';

import { isSafePushEndpoint, MAX_PUSH_ENDPOINT_LEN } from '../src/utils/pushEndpoint';

describe('isSafePushEndpoint (SEC-20260621-011)', () => {
  it('accepts a normal HTTPS push service endpoint', () => {
    expect(isSafePushEndpoint('https://fcm.googleapis.com/fcm/send/abc123')).toBe(true);
    expect(isSafePushEndpoint('https://updates.push.services.mozilla.com/wpush/v2/xyz')).toBe(true);
  });

  it('rejects non-HTTPS endpoints', () => {
    expect(isSafePushEndpoint('http://fcm.googleapis.com/fcm/send/abc')).toBe(false);
    expect(isSafePushEndpoint('ftp://example.com/x')).toBe(false);
  });

  it('rejects loopback hosts', () => {
    expect(isSafePushEndpoint('https://localhost/x')).toBe(false);
    expect(isSafePushEndpoint('https://127.0.0.1/x')).toBe(false);
    expect(isSafePushEndpoint('https://[::1]/x')).toBe(false);
  });

  it('rejects RFC1918 private hosts', () => {
    expect(isSafePushEndpoint('https://10.0.0.5/x')).toBe(false);
    expect(isSafePushEndpoint('https://192.168.1.1/x')).toBe(false);
    expect(isSafePushEndpoint('https://172.16.5.5/x')).toBe(false);
  });

  it('rejects link-local / cloud metadata hosts', () => {
    expect(isSafePushEndpoint('https://169.254.169.254/latest/meta-data')).toBe(false);
    expect(isSafePushEndpoint('https://[fe80::1]/x')).toBe(false);
  });

  it('rejects IPv4-mapped IPv6 loopback', () => {
    expect(isSafePushEndpoint('https://[::ffff:127.0.0.1]/x')).toBe(false);
  });

  it('rejects oversized endpoints and garbage', () => {
    expect(isSafePushEndpoint('https://example.com/' + 'a'.repeat(MAX_PUSH_ENDPOINT_LEN))).toBe(false);
    expect(isSafePushEndpoint('not-a-url')).toBe(false);
    expect(isSafePushEndpoint('')).toBe(false);
  });
});
