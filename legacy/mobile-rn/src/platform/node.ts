// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { webcrypto } from 'node:crypto'
import type { KeyValueStore, Platform, PlatformCrypto, SecureSecretStore } from './adapter'

/**
 * Node reference adapter, used by the test suite. It uses the same SubtleCrypto
 * PBKDF2 call the web client uses, so the three implementations stay one line apart.
 */
export const nodePlatform: PlatformCrypto = {
  async pbkdf2(password, salt, iterations, keyLenBytes) {
    const keyMaterial = await webcrypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
    const bits = await webcrypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      keyMaterial,
      keyLenBytes * 8
    )
    return new Uint8Array(bits)
  },

  randomBytes(length) {
    return webcrypto.getRandomValues(new Uint8Array(length))
  },
}

/**
 * In-memory key-value store. Values are round-tripped through JSON so the tests
 * exercise the same serialisation boundary a real database imposes, rather than
 * silently sharing object references with the caller.
 */
export function createMemoryKeyValueStore(): KeyValueStore & { size(): number } {
  const map = new Map<string, string>()
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const raw = map.get(key)
      return raw === undefined ? undefined : (JSON.parse(raw) as T)
    },
    async set(key, value) {
      map.set(key, JSON.stringify(value))
    },
    async del(key) {
      map.delete(key)
    },
    async clear() {
      map.clear()
    },
    size() {
      return map.size
    },
  }
}

/**
 * In-memory stand-in for the OS keystore. Deliberately a separate map from the
 * key-value store: the whole point of the device secret is that it does NOT live
 * in app storage, and the tests must be able to wipe one without the other to
 * prove it (see the vault tests).
 */
export function createMemorySecretStore(): SecureSecretStore {
  const map = new Map<string, string>()
  return {
    async getSecret(key) {
      return map.get(key) ?? null
    },
    async setSecret(key, value) {
      map.set(key, value)
    },
    async deleteSecret(key) {
      map.delete(key)
    },
  }
}

/** A complete platform bundle for tests. */
export function createNodeTestPlatform(): Platform {
  return {
    crypto: nodePlatform,
    kv: createMemoryKeyValueStore(),
    secure: createMemorySecretStore(),
  }
}
