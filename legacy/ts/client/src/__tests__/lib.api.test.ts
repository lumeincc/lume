// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for lib/api.ts
 * Covers: request() helper, authApi, messagesApi, healthApi
 * Mocks: global.fetch, crypto/keyVault vaultSignRequest
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Hoisted mocks ───────────────��────────────────────────────────────────────

const mocks = vi.hoisted(() => ({
  vaultHasKeys: vi.fn(() => false),
  vaultSignRequest: vi.fn((_method: string, path: string) => ({
    'X-Lume-Identity-Key': 'test-signing-pk',
    'X-Lume-Signature': 'mock-base64-signature',
    'X-Lume-Timestamp': Date.now().toString(),
    'X-Lume-Nonce': 'mock-nonce',
    'X-Lume-Path': path.startsWith('/') ? path : `/${path}`,
  })),
}));

vi.mock('@/crypto/keyVault', () => ({
  vaultHasKeys: mocks.vaultHasKeys,
  vaultSignRequest: mocks.vaultSignRequest,
}));

import { authApi, messagesApi, healthApi, profileApi, filesApi, groupsApi } from '@/lib/api';

// ── Helpers ─────────────────────────────────────��────────────────────────────

function jsonResponse(body: unknown, status = 200, headers?: Record<string, string>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function textResponse(body: string, status = 200) {
  return new Response(body, {
    status,
    headers: { 'content-type': 'text/plain' },
  });
}

// ── Setup ──────────────────────────────────────────────────���─────────────────

const fetchSpy = vi.fn<(...args: unknown[]) => Promise<Response>>();

beforeEach(() => {
  vi.stubGlobal('fetch', fetchSpy);
  fetchSpy.mockReset();
  mocks.vaultSignRequest.mockClear();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── request() core behaviour (tested via healthApi.check) ────────────────────

describe('request() core', () => {
  it('sends correct URL with Content-Type header', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ status: 'ok' }));

    await healthApi.check();

    expect(fetchSpy).toHaveBeenCalledOnce();
    const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://localhost:3001/api/health');
    expect(opts.headers).toEqual(expect.objectContaining({ 'Content-Type': 'application/json' }));
  });

  it('returns data on successful JSON response', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ status: 'ok', timestamp: '2025-01-01' }));

    const result = await healthApi.check();

    expect(result.error).toBeUndefined();
    expect(result.data).toEqual({ status: 'ok', timestamp: '2025-01-01' });
  });

  it('returns error on 429 (rate limited)', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({}, 429));

    const result = await healthApi.check();

    expect(result.error).toBe('Too many requests. Please try again later.');
    expect(result.data).toBeUndefined();
  });

  it('returns error on non-ok status with error field', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ error: 'Not found' }, 404));

    const result = await healthApi.check();

    expect(result.error).toBe('Not found');
  });

  it('returns generic error on non-ok status without error field', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ foo: 'bar' }, 500));

    const result = await healthApi.check();

    expect(result.error).toBe('Request failed: 500');
  });

  it('returns "Network error" on fetch rejection', async () => {
    fetchSpy.mockRejectedValue(new TypeError('Failed to fetch'));

    const result = await healthApi.check();

    expect(result.error).toBe('Network error');
  });

  it('returns "Invalid server response" on invalid JSON', async () => {
    // Response with JSON content-type but invalid body
    const resp = new Response('not-json!!!', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    // Override .json() to throw
    const origJson = resp.json.bind(resp);
    let called = false;
    resp.json = async () => {
      if (!called) {
        called = true;
        return origJson();
      }
      throw new Error('bad json');
    };
    fetchSpy.mockResolvedValue(resp);

    const result = await healthApi.check();

    expect(result.error).toBe('Invalid server response');
  });

  it('handles non-JSON (text) response body on an error status', async () => {
    fetchSpy.mockResolvedValue(textResponse('Short error', 503));

    const result = await healthApi.check();

    expect(result.error).toBe('Short error');
  });

  it('truncates long text responses to generic "Server error"', async () => {
    const longText = 'x'.repeat(200);
    fetchSpy.mockResolvedValue(textResponse(longText, 503));

    const result = await healthApi.check();

    expect(result.error).toBe('Server error');
  });
});

// ── authApi ─────────��────────────────────────────��───────────────────────────

describe('authApi', () => {
  describe('register', () => {
    it('sends POST with register data', async () => {
      const regData = {
        username: 'alice',
        identityKey: 'ik',
        signedPrekey: 'spk',
        signedPrekeySignature: 'sig',
        oneTimePrekeys: [{ id: '1', publicKey: 'pk1' }],
      };
      const regId = '11111111-1111-4111-8111-111111111111';
      fetchSpy.mockResolvedValue(jsonResponse({ id: regId, username: 'alice', message: 'ok' }));

      const result = await authApi.register(regData);

      const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(opts.method).toBe('POST');
      expect(JSON.parse(opts.body as string)).toEqual(regData);
      expect(result.data).toEqual({ id: regId, username: 'alice', message: 'ok' });
    });
  });

  describe('checkUsername', () => {
    it('sends GET to correct endpoint', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ available: true }));

      const result = await authApi.checkUsername('bob');

      const [url] = fetchSpy.mock.calls[0] as [string];
      expect(url).toContain('/auth/check/bob');
      expect(result.data?.available).toBe(true);
    });
  });

  describe('getUser', () => {
    it('signs the request via vault and sends GET', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ id: 'u1', username: 'bob' }));

      await authApi.getUser('bob');

      expect(mocks.vaultSignRequest).toHaveBeenCalledWith('GET', '/auth/user/bob', {});
      const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(url).toContain('/auth/user/bob');
      const headers = opts.headers as Record<string, string>;
      expect(headers['X-Lume-Identity-Key']).toBe('test-signing-pk');
      expect(headers['X-Lume-Signature']).toBe('mock-base64-signature');
      expect(headers['X-Lume-Timestamp']).toBeDefined();
      expect(headers['X-Lume-Nonce']).toBeDefined();
    });
  });

  describe('getBundle', () => {
    it('sends signed POST with username in body', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ id: 'u1' }));

      await authApi.getBundle('bob');

      const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(url).toContain('/auth/bundle');
      expect(opts.method).toBe('POST');
      expect(JSON.parse(opts.body as string)).toEqual({ username: 'bob' });
    });
  });

  describe('uploadPrekeys', () => {
    it('sends signed POST with prekeys payload', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ message: 'ok', totalPrekeys: 10 }));

      const result = await authApi.uploadPrekeys('u1', [{ id: 'k1', publicKey: 'pk1' }]);

      const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(JSON.parse(opts.body as string)).toEqual({
        userId: 'u1',
        prekeys: [{ id: 'k1', publicKey: 'pk1' }],
      });
      expect(result.data?.totalPrekeys).toBe(10);
    });
  });

  describe('updateSignedPrekey', () => {
    it('sends signed POST', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ message: 'ok' }));

      await authApi.updateSignedPrekey('u1', 'spk', 'sig');

      const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(url).toContain('/auth/keys');
      expect(JSON.parse(opts.body as string)).toEqual({
        userId: 'u1',
        signedPrekey: 'spk',
        signedPrekeySignature: 'sig',
      });
    });
  });

  describe('deleteAccount', () => {
    it('sends signed DELETE', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ message: 'deleted' }));

      await authApi.deleteAccount('u1');

      const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(url).toContain('/auth/user/u1');
      expect(opts.method).toBe('DELETE');
    });
  });

  describe('getSession', () => {
    it('sends signed POST and returns token', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ token: 'jwt-token', expiresIn: 3600 }));

      const result = await authApi.getSession('u1');

      expect(result.data?.token).toBe('jwt-token');
      expect(result.data?.expiresIn).toBe(3600);
    });
  });

  describe('blockUser / unblockUser / getBlockedUsers', () => {
    it('blockUser sends signed POST', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ ok: true }));

      const result = await authApi.blockUser('blocked-id');

      const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(url).toContain('/auth/block');
      expect(JSON.parse(opts.body as string)).toEqual({ blockedId: 'blocked-id' });
      expect(result.data?.ok).toBe(true);
    });

    it('unblockUser sends signed POST', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ ok: true }));

      await authApi.unblockUser('blocked-id');

      const [url] = fetchSpy.mock.calls[0] as [string];
      expect(url).toContain('/auth/unblock');
    });

    it('getBlockedUsers sends signed GET', async () => {
      const ids = [
        '11111111-1111-4111-8111-111111111111',
        '22222222-2222-4222-8222-222222222222',
      ];
      fetchSpy.mockResolvedValue(jsonResponse({ blockedIds: ids }));

      const result = await authApi.getBlockedUsers();

      const [url] = fetchSpy.mock.calls[0] as [string];
      expect(url).toContain('/auth/blocked');
      expect(result.data?.blockedIds).toEqual(ids);
    });
  });
});

// ── messagesApi ───────��─────────────────────────────────────────��────────────

describe('messagesApi', () => {
  describe('send', () => {
    it('sends signed POST with message data', async () => {
      const msgId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
      fetchSpy.mockResolvedValue(jsonResponse({ messageId: msgId, delivered: true }));

      const data = { senderId: 'u1', recipientId: 'u2', encryptedPayload: 'enc' };
      const result = await messagesApi.send(data);

      const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(url).toContain('/messages/send');
      expect(opts.method).toBe('POST');
      expect(result.data?.messageId).toBe(msgId);
    });
  });

  describe('getPending', () => {
    it('sends signed GET', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ messages: [] }));

      const result = await messagesApi.getPending('u1');

      const [url] = fetchSpy.mock.calls[0] as [string];
      expect(url).toContain('/messages/pending/u1');
      expect(result.data?.messages).toEqual([]);
    });
  });

  describe('acknowledge', () => {
    it('sends signed DELETE', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ message: 'ack' }));

      await messagesApi.acknowledge('m1');

      const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(url).toContain('/messages/m1');
      expect(opts.method).toBe('DELETE');
    });
  });

  describe('acknowledgeBatch', () => {
    it('sends signed POST with messageIds', async () => {
      fetchSpy.mockResolvedValue(jsonResponse({ acknowledged: 3 }));

      const result = await messagesApi.acknowledgeBatch(['m1', 'm2', 'm3']);

      const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
      expect(JSON.parse(opts.body as string)).toEqual({ messageIds: ['m1', 'm2', 'm3'] });
      expect(result.data?.acknowledged).toBe(3);
    });
  });
});

// ── signRequest header validation ────���───────────────────────────────────────

describe('response validation — fail closed (SEC-20260621-007)', () => {
  it('rejects a malformed session response', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ token: 123 })); // wrong type + missing expiresIn
    const result = await authApi.getSession('u1');
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });

  it('rejects a malformed pending-messages response', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ messages: [{ id: 'm1' }] })); // missing message fields
    const result = await messagesApi.getPending('u1');
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });

  it('rejects a malformed profile response', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ id: 'u1' })); // missing username/displayName/avatarFileId
    const result = await profileApi.get('u1');
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });

  it('rejects a malformed file-download response', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ fileId: 'f1' })); // missing data/mimeHint/size
    const result = await filesApi.download('f1');
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });

  it('accepts a well-formed session response', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ token: 'jwt', expiresIn: 600 }));
    const result = await authApi.getSession('u1');
    expect(result.error).toBeUndefined();
    expect(result.data?.token).toBe('jwt');
  });

  it('rejects a malformed group-create response (missing creator_id/created_at)', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ id: 'g1', name: 'Group', members: [] }));
    const result = await groupsApi.create('Group', []);
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });

  it('accepts a well-formed group-create response', async () => {
    const creatorId = '11111111-1111-4111-8111-111111111111';
    fetchSpy.mockResolvedValue(
      jsonResponse({
        id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        name: 'Group',
        creator_id: creatorId,
        created_at: 1700000000000,
        members: [{ user_id: creatorId, username: 'alice', role: 'admin' }],
      }),
    );
    const result = await groupsApi.create('Group', []);
    expect(result.error).toBeUndefined();
    expect(result.data?.creator_id).toBe(creatorId);
  });

  it('rejects a malformed block response (wrong ok type)', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ ok: 'yes' }));
    const result = await authApi.blockUser('blocked-id');
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });

  it('rejects a malformed uploadPrekeys response (missing totalPrekeys)', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ message: 'ok' }));
    const result = await authApi.uploadPrekeys('u1', [{ id: 'k1', publicKey: 'pk1' }]);
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });

  it('rejects a malformed single-acknowledge response (missing message)', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ ok: true }));
    const result = await messagesApi.acknowledge('m1');
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });

  it('rejects a malformed health response (missing timestamp)', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ status: 'ok' }));
    const result = await healthApi.check();
    expect(result.error).toBe('Invalid server response');
    expect(result.data).toBeUndefined();
  });
});

describe('signRequest headers', () => {
  it('includes all X-Lume-* headers on signed requests', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ token: 'jwt' }));

    await authApi.getSession('u1');

    const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit];
    const headers = opts.headers as Record<string, string>;

    expect(headers).toHaveProperty('X-Lume-Identity-Key');
    expect(headers).toHaveProperty('X-Lume-Signature');
    expect(headers).toHaveProperty('X-Lume-Timestamp');
    expect(headers).toHaveProperty('X-Lume-Nonce');
    expect(headers).toHaveProperty('X-Lume-Path');
    expect(headers['X-Lume-Path']).toBe('/auth/session');
  });
});
