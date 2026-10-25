// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { describe, it, expect } from 'vitest';

import { redactSensitivePath } from '../src/utils/logRedaction';

const UUID = '11111111-1111-4111-8111-111111111111';

describe('redactSensitivePath (SEC-20260621-021, SEC-20260721-027)', () => {
  it('redacts invite tokens in resolve-invite paths', () => {
    expect(redactSensitivePath('/api/auth/resolve-invite/abc123SECRETtoken')).toBe(
      '/api/auth/resolve-invite/:token',
    );
    expect(redactSensitivePath('/auth/resolve-invite/zzz')).toBe('/auth/resolve-invite/:token');
  });

  it('redacts UUID identifiers in every id-bearing path', () => {
    expect(redactSensitivePath(`/api/profile/${UUID}`)).toBe('/api/profile/:id');
    expect(redactSensitivePath(`/api/messages/pending/${UUID}`)).toBe(
      '/api/messages/pending/:id',
    );
    expect(redactSensitivePath(`/api/messages/${UUID}`)).toBe('/api/messages/:id');
    expect(redactSensitivePath(`/api/files/${UUID}`)).toBe('/api/files/:id');
    expect(redactSensitivePath(`/api/files/${UUID}/raw`)).toBe('/api/files/:id/raw');
    expect(redactSensitivePath(`/api/groups/${UUID}`)).toBe('/api/groups/:id');
    expect(redactSensitivePath(`/api/groups/${UUID}/members/${UUID}`)).toBe(
      '/api/groups/:id/members/:id',
    );
    // DELETE /auth/user/:userId carries a UUID, redacted by shape.
    expect(redactSensitivePath(`/api/auth/user/${UUID}`)).toBe('/api/auth/user/:id');
  });

  it('redacts usernames after /user/ and /check/', () => {
    expect(redactSensitivePath('/api/auth/user/alice')).toBe('/api/auth/user/:username');
    expect(redactSensitivePath('/api/auth/check/bob_99')).toBe('/api/auth/check/:username');
  });

  it('leaves static paths unchanged', () => {
    expect(redactSensitivePath('/api/health')).toBe('/api/health');
    expect(redactSensitivePath('/api/messages/send')).toBe('/api/messages/send');
    expect(redactSensitivePath('/api/messages/acknowledge')).toBe('/api/messages/acknowledge');
    expect(redactSensitivePath('/api/groups')).toBe('/api/groups');
  });
});
