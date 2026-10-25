// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Key Vault — centralized module-scoped storage for all private key material.
 *
 * Holds identityKeys, masterKey, and Double Ratchet sessions in module-scoped
 * variables (not in Zustand state). Exposes controlled accessor functions so
 * callers never touch raw key material directly from global state.
 *
 * This module must NOT import from stores or lib/api.ts to avoid circular deps.
 */

import { sign, zeroBytes, type IdentityKeys, type KeyPair, type SigningKeyPair } from './keys';
import { encodeBase64 } from 'tweetnacl-util';
import { clearCachedMasterKey } from './storage';
import type { SerializedSession } from './ratchet';

// ==================== Module-scoped state ====================

let _identityKeys: IdentityKeys | null = null;
let _masterKey: Uint8Array | null = null;
let _sessions: Record<string, SerializedSession> = {};
let _attachmentKeys: Record<string, { key: string; nonce: string }> = {};
const _sessionChangeListeners: Set<() => void> = new Set();

// ==================== Initialization ====================

/**
 * Stores identity keys and master key in the vault.
 * Called during setup, unlock, and recovery flows.
 */
export function vaultSetAuth(identityKeys: IdentityKeys, masterKey: Uint8Array): void {
  _identityKeys = identityKeys;
  _masterKey = masterKey;
}

/**
 * Replaces the master key in the vault (e.g. after PIN change).
 * Zeroes the old key before replacing.
 */
export function vaultSetMasterKey(key: Uint8Array): void {
  if (_masterKey) {
    zeroBytes(_masterKey);
  }
  _masterKey = key;
}

/**
 * Sets ratchet sessions in the vault (initial load from IndexedDB).
 */
export function vaultSetSessions(sessions: Record<string, SerializedSession>): void {
  _sessions = { ...sessions };
  notifySessionListeners();
}

// ==================== Cleanup ====================

/**
 * Zeroes and clears all key material from the vault.
 * Called on logout, panic wipe, and clearAuth.
 */
export function vaultClear(): void {
  if (_masterKey) {
    zeroBytes(_masterKey);
  }
  _masterKey = null;
  _identityKeys = null;
  _sessions = {};
  _attachmentKeys = {};
  clearCachedMasterKey();
  notifySessionListeners();
}

// ==================== API Request Signing ====================

/**
 * Signs an API request using the vault's identity signing key.
 * Replicates the exact signing logic from lib/api.ts signRequest().
 *
 * Returns the headers object to attach to the fetch call.
 * Throws if the vault has no identity keys.
 */
export function vaultSignRequest(
  method: string,
  endpoint: string,
  body: unknown,
): Record<string, string> {
  if (!_identityKeys) {
    throw new Error('Vault: no identity keys — cannot sign request');
  }

  const timestamp = Date.now().toString();
  const crypto = globalThis.crypto;
  const nonce =
    crypto &&
    typeof (crypto as Crypto & { randomUUID?: () => string }).randomUUID ===
      'function'
      ? (crypto as Crypto & { randomUUID: () => string }).randomUUID()
      : (() => {
          const bytes = new Uint8Array(16);
          crypto.getRandomValues(bytes);
          return `${Date.now()}-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
        })();
  const normalizedMethod = method.toUpperCase();
  const normalizedPath = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const bodyString =
    body && Object.keys(body as object).length > 0
      ? JSON.stringify(body)
      : '';
  const message = `${timestamp}.${nonce}.${normalizedMethod}.${normalizedPath}.${bodyString}`;

  const messageBytes = new TextEncoder().encode(message);
  const signature = sign(messageBytes, _identityKeys.signing.secretKey);

  return {
    'X-Lume-Identity-Key': _identityKeys.signing.publicKey,
    'X-Lume-Signature': encodeBase64(signature),
    'X-Lume-Timestamp': timestamp,
    'X-Lume-Nonce': nonce,
    'X-Lume-Path': normalizedPath,
  };
}

/**
 * Returns the signing public key (Ed25519) from the vault.
 * Throws if the vault has no identity keys.
 */
export function vaultGetSigningPublicKey(): string {
  if (!_identityKeys) {
    throw new Error('Vault: no identity keys — cannot get signing public key');
  }
  return _identityKeys.signing.publicKey;
}

// ==================== Public Key Accessors (safe) ====================

/**
 * Returns public keys only (no secret material).
 * Returns null if the vault has no identity keys.
 */
export function vaultGetPublicKeys(): {
  signingPublicKey: string;
  exchangePublicKey: string;
} | null {
  if (!_identityKeys) {
    return null;
  }
  return {
    signingPublicKey: _identityKeys.signing.publicKey,
    exchangePublicKey: _identityKeys.exchange.publicKey,
  };
}

/**
 * Returns true if the vault holds identity keys.
 */
export function vaultHasKeys(): boolean {
  return _identityKeys !== null;
}

/**
 * Returns true if the vault holds a master key.
 */
export function vaultHasMasterKey(): boolean {
  return _masterKey !== null;
}

// ==================== Master Key Accessor ====================

/**
 * Returns the master key for IndexedDB encryption operations.
 * Throws if the vault has no master key — fail closed.
 */
export function vaultGetMasterKey(): Uint8Array {
  if (!_masterKey) {
    throw new Error('Vault: no master key');
  }
  return _masterKey;
}

// ==================== Session CRUD ====================

/**
 * Notifies all session change listeners.
 */
function notifySessionListeners(): void {
  for (const listener of _sessionChangeListeners) {
    listener();
  }
}

/**
 * Upserts a ratchet session for a contact.
 * Uses immutable update — never mutates existing _sessions reference.
 */
export function vaultUpsertSession(
  contactId: string,
  session: SerializedSession,
): void {
  _sessions = { ..._sessions, [contactId]: session };
  notifySessionListeners();
}

/**
 * Deletes a ratchet session for a contact.
 * Uses immutable update — never mutates existing _sessions reference.
 */
export function vaultDeleteSession(contactId: string): void {
  const rest = { ..._sessions };
  delete rest[contactId];
  _sessions = rest;
  notifySessionListeners();
}

/**
 * Returns the ratchet session for a contact, or undefined if none exists.
 */
export function vaultGetSession(
  contactId: string,
): SerializedSession | undefined {
  return _sessions[contactId];
}

/**
 * Returns a shallow copy of all ratchet sessions.
 */
export function vaultGetAllSessions(): Record<string, SerializedSession> {
  return { ..._sessions };
}

/**
 * Returns true if a ratchet session exists for the given contact.
 */
export function vaultHasSession(contactId: string): boolean {
  return contactId in _sessions;
}

// ==================== Session Change Subscription ====================

/**
 * Subscribes to session changes. Returns an unsubscribe function.
 * Listeners are called whenever sessions are upserted, deleted, set, or cleared.
 */
export function vaultSubscribeSessionChanges(
  listener: () => void,
): () => void {
  _sessionChangeListeners.add(listener);
  return () => {
    _sessionChangeListeners.delete(listener);
  };
}

// ==================== Key Pair Accessors ====================

/**
 * Returns the exchange key pair (X25519) from the vault.
 * Needed by x3dhInitiate/x3dhRespond in the crypto layer.
 * Throws if the vault has no identity keys — fail closed.
 */
export function vaultGetExchangeKeyPair(): KeyPair {
  if (!_identityKeys) {
    throw new Error('Vault: no identity keys — cannot get exchange key pair');
  }
  return _identityKeys.exchange;
}

/**
 * Returns the signing key pair (Ed25519) from the vault.
 * Needed by generateSignedPreKey in spkRotation.
 * Throws if the vault has no identity keys — fail closed.
 */
export function vaultGetSigningKeyPair(): SigningKeyPair {
  if (!_identityKeys) {
    throw new Error('Vault: no identity keys — cannot get signing key pair');
  }
  return _identityKeys.signing;
}

// ==================== Attachment decrypt keys ====================
// File decrypt key/nonce live here (module-scoped), keyed by fileId — never in
// Zustand/message state. Persisted encrypted via storage.saveAttachmentKeys.
// SEC-20260621-004.

export function vaultSetAttachmentKeys(keys: Record<string, { key: string; nonce: string }>): void {
  _attachmentKeys = { ...keys };
}

export function vaultSetAttachmentKey(fileId: string, key: string, nonce: string): void {
  _attachmentKeys = { ..._attachmentKeys, [fileId]: { key, nonce } };
}

export function vaultGetAttachmentKey(fileId: string): { key: string; nonce: string } | undefined {
  return _attachmentKeys[fileId];
}

export function vaultGetAllAttachmentKeys(): Record<string, { key: string; nonce: string }> {
  return { ..._attachmentKeys };
}
