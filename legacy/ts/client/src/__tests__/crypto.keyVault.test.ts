// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for crypto/keyVault.ts
 * Covers: vault lifecycle, signing, master key, session CRUD,
 * session subscriptions, memory zeroing, key pair accessors.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock @/crypto/storage for clearCachedMasterKey
vi.mock('@/crypto/storage', () => ({
  clearCachedMasterKey: vi.fn(),
}));

// Mock @/crypto/keys for sign function (avoid real NaCl in unit tests)
vi.mock('@/crypto/keys', () => ({
  sign: vi.fn(() => new Uint8Array(64).fill(0xAB)),
  zeroBytes: vi.fn((arr: Uint8Array) => arr.fill(0)),
}));

// Mock tweetnacl-util encodeBase64
vi.mock('tweetnacl-util', () => ({
  encodeBase64: vi.fn((arr: Uint8Array) =>
    Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join(''),
  ),
}));

import {
  vaultSetAuth,
  vaultClear,
  vaultSetMasterKey,
  vaultSetSessions,
  vaultSignRequest,
  vaultGetSigningPublicKey,
  vaultGetPublicKeys,
  vaultHasKeys,
  vaultHasMasterKey,
  vaultGetMasterKey,
  vaultUpsertSession,
  vaultDeleteSession,
  vaultGetSession,
  vaultGetAllSessions,
  vaultHasSession,
  vaultSubscribeSessionChanges,
  vaultGetExchangeKeyPair,
  vaultGetSigningKeyPair,
} from '@/crypto/keyVault';
import { clearCachedMasterKey } from '@/crypto/storage';
import { zeroBytes } from '@/crypto/keys';
import type { SerializedSession } from '@/crypto/ratchet';

// ── Test data ────────────────────────────────────────────────────────────────

const mockIdentityKeys = {
  signing: { publicKey: 'sigPub123', secretKey: 'sigSec456' },
  exchange: { publicKey: 'exchPub789', secretKey: 'exchSec012' },
};

const mockSession: SerializedSession = {
  dhSendingKeyPair: { publicKey: 'dhsPub', secretKey: 'dhsSec' },
  dhReceivingPublicKey: 'dhrPub',
  rootKey: 'rootKey',
  sendingChainKey: 'chainKeySend',
  receivingChainKey: 'chainKeyRecv',
  sendingMessageNumber: 0,
  receivingMessageNumber: 0,
  previousSendingChainLength: 0,
  skippedMessageKeys: [],
};

const mockSession2: SerializedSession = {
  dhSendingKeyPair: { publicKey: 'dhsPub2', secretKey: 'dhsSec2' },
  dhReceivingPublicKey: 'dhrPub2',
  rootKey: 'rootKey2',
  sendingChainKey: 'chainKeySend2',
  receivingChainKey: 'chainKeyRecv2',
  sendingMessageNumber: 5,
  receivingMessageNumber: 3,
  previousSendingChainLength: 1,
  skippedMessageKeys: [],
};

// ── Setup ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  vaultClear();
  vi.clearAllMocks();
});

// ── vaultSetAuth / vaultClear lifecycle ──────────────────────────────────────

describe('vaultSetAuth / vaultClear lifecycle', () => {
  it('stores keys and reports hasKeys=true', () => {
    expect(vaultHasKeys()).toBe(false);
    expect(vaultHasMasterKey()).toBe(false);

    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));

    expect(vaultHasKeys()).toBe(true);
    expect(vaultHasMasterKey()).toBe(true);
  });

  it('vaultClear resets all state', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));
    vaultUpsertSession('contact-1', mockSession);

    vaultClear();

    expect(vaultHasKeys()).toBe(false);
    expect(vaultHasMasterKey()).toBe(false);
    expect(vaultHasSession('contact-1')).toBe(false);
    expect(vaultGetPublicKeys()).toBeNull();
  });

  it('vaultClear calls clearCachedMasterKey from storage', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));
    vaultClear();
    // Called once from the beforeEach vaultClear + once from this vaultClear
    expect(clearCachedMasterKey).toHaveBeenCalled();
  });
});

// ── vaultSignRequest ─────────────────────────────────────────────────────────

describe('vaultSignRequest', () => {
  it('returns valid headers when keys are set', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));

    const headers = vaultSignRequest('POST', '/auth/session', { userId: '123' });

    expect(headers['X-Lume-Identity-Key']).toBe('sigPub123');
    expect(headers['X-Lume-Signature']).toBeDefined();
    expect(headers['X-Lume-Timestamp']).toBeDefined();
    expect(headers['X-Lume-Nonce']).toBeDefined();
    expect(headers['X-Lume-Path']).toBe('/auth/session');
  });

  it('normalizes path to start with /', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));

    const headers = vaultSignRequest('GET', 'no-leading-slash', {});
    expect(headers['X-Lume-Path']).toBe('/no-leading-slash');
  });

  it('throws when no identity keys are set', () => {
    expect(() => vaultSignRequest('GET', '/test', {})).toThrow(
      'Vault: no identity keys',
    );
  });
});

// ── vaultGetMasterKey ────────────────────────────────────────────────────────

describe('vaultGetMasterKey', () => {
  it('returns master key when set', () => {
    const mk = new Uint8Array(32).fill(7);
    vaultSetAuth(mockIdentityKeys, mk);

    expect(vaultGetMasterKey()).toBe(mk);
  });

  it('throws when not set', () => {
    expect(() => vaultGetMasterKey()).toThrow('Vault: no master key');
  });

  it('vaultSetMasterKey replaces the key', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));
    const newKey = new Uint8Array(32).fill(9);
    vaultSetMasterKey(newKey);

    expect(vaultGetMasterKey()).toBe(newKey);
  });

  it('vaultSetMasterKey zeroes old key', () => {
    const oldKey = new Uint8Array(32).fill(1);
    vaultSetAuth(mockIdentityKeys, oldKey);
    vi.clearAllMocks(); // clear the mock call count

    const newKey = new Uint8Array(32).fill(9);
    vaultSetMasterKey(newKey);

    expect(zeroBytes).toHaveBeenCalledWith(oldKey);
  });
});

// ── Session CRUD ─────────────────────────────────────────────────────────────

describe('session CRUD', () => {
  it('upsertSession adds a session', () => {
    vaultUpsertSession('alice', mockSession);

    expect(vaultHasSession('alice')).toBe(true);
    expect(vaultGetSession('alice')).toEqual(mockSession);
  });

  it('getSession returns undefined for missing contact', () => {
    expect(vaultGetSession('nonexistent')).toBeUndefined();
  });

  it('hasSession returns false for missing contact', () => {
    expect(vaultHasSession('nonexistent')).toBe(false);
  });

  it('deleteSession removes a session', () => {
    vaultUpsertSession('alice', mockSession);
    vaultDeleteSession('alice');

    expect(vaultHasSession('alice')).toBe(false);
    expect(vaultGetSession('alice')).toBeUndefined();
  });

  it('getAllSessions returns shallow copy of all sessions', () => {
    vaultUpsertSession('alice', mockSession);
    vaultUpsertSession('bob', mockSession2);

    const all = vaultGetAllSessions();
    expect(Object.keys(all)).toHaveLength(2);
    expect(all['alice']).toEqual(mockSession);
    expect(all['bob']).toEqual(mockSession2);
  });

  it('getAllSessions returns a copy, not a reference', () => {
    vaultUpsertSession('alice', mockSession);
    const copy1 = vaultGetAllSessions();
    vaultUpsertSession('bob', mockSession2);
    const copy2 = vaultGetAllSessions();

    // copy1 should not have bob
    expect(Object.keys(copy1)).toHaveLength(1);
    expect(Object.keys(copy2)).toHaveLength(2);
  });

  it('vaultSetSessions replaces all sessions', () => {
    vaultUpsertSession('alice', mockSession);
    vaultSetSessions({ bob: mockSession2 });

    expect(vaultHasSession('alice')).toBe(false);
    expect(vaultHasSession('bob')).toBe(true);
  });
});

// ── vaultSubscribeSessionChanges ─────────────────────────────────────────────

describe('vaultSubscribeSessionChanges', () => {
  it('fires on upsert', () => {
    const listener = vi.fn();
    vaultSubscribeSessionChanges(listener);

    vaultUpsertSession('alice', mockSession);

    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('fires on delete', () => {
    vaultUpsertSession('alice', mockSession);

    const listener = vi.fn();
    vaultSubscribeSessionChanges(listener);

    vaultDeleteSession('alice');

    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('fires on setSessions', () => {
    const listener = vi.fn();
    vaultSubscribeSessionChanges(listener);

    vaultSetSessions({ bob: mockSession2 });

    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('fires on vaultClear', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));
    vaultUpsertSession('alice', mockSession);

    const listener = vi.fn();
    vaultSubscribeSessionChanges(listener);

    vaultClear();

    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('unsubscribe stops notifications', () => {
    const listener = vi.fn();
    const unsub = vaultSubscribeSessionChanges(listener);

    vaultUpsertSession('alice', mockSession);
    expect(listener).toHaveBeenCalledTimes(1);

    unsub();

    vaultUpsertSession('bob', mockSession2);
    expect(listener).toHaveBeenCalledTimes(1); // no additional call
  });
});

// ── Memory zeroing ───────────────────────────────────────────────────────────

describe('memory zeroing', () => {
  it('vaultClear zeroes masterKey via zeroBytes', () => {
    const mk = new Uint8Array(32).fill(5);
    vaultSetAuth(mockIdentityKeys, mk);
    vi.clearAllMocks();

    vaultClear();

    expect(zeroBytes).toHaveBeenCalledWith(mk);
  });
});

// ── Public key accessors ─────────────────────────────────────────────────────

describe('vaultGetPublicKeys', () => {
  it('returns public keys when set', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));

    const pubKeys = vaultGetPublicKeys();
    expect(pubKeys).toEqual({
      signingPublicKey: 'sigPub123',
      exchangePublicKey: 'exchPub789',
    });
  });

  it('returns null when not set', () => {
    expect(vaultGetPublicKeys()).toBeNull();
  });
});

describe('vaultGetSigningPublicKey', () => {
  it('returns signing public key when set', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));
    expect(vaultGetSigningPublicKey()).toBe('sigPub123');
  });

  it('throws when not set', () => {
    expect(() => vaultGetSigningPublicKey()).toThrow('Vault: no identity keys');
  });
});

// ── Key pair accessors ───────────────────────────────────────────────────────

describe('vaultGetExchangeKeyPair', () => {
  it('returns exchange key pair when set', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));

    const kp = vaultGetExchangeKeyPair();
    expect(kp.publicKey).toBe('exchPub789');
    expect(kp.secretKey).toBe('exchSec012');
  });

  it('throws when not set', () => {
    expect(() => vaultGetExchangeKeyPair()).toThrow(
      'Vault: no identity keys — cannot get exchange key pair',
    );
  });
});

describe('vaultGetSigningKeyPair', () => {
  it('returns signing key pair when set', () => {
    vaultSetAuth(mockIdentityKeys, new Uint8Array(32).fill(1));

    const kp = vaultGetSigningKeyPair();
    expect(kp.publicKey).toBe('sigPub123');
    expect(kp.secretKey).toBe('sigSec456');
  });

  it('throws when not set', () => {
    expect(() => vaultGetSigningKeyPair()).toThrow(
      'Vault: no identity keys — cannot get signing key pair',
    );
  });
});
