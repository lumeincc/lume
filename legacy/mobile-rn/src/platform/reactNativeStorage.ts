// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * On-device implementations of the storage seam.
 *
 * These import native modules, so they are kept out of the Node-testable modules
 * (the tests drive the same interfaces through src/platform/node.ts instead).
 *
 *   - KeyValueStore   → expo-sqlite. Holds only ciphertext; see src/vault.ts.
 *   - SecureSecretStore → expo-secure-store, which is backed by the Android
 *     Keystore / iOS Keychain. The device secret lives here and nowhere else,
 *     which is what stops an attacker with a copy of the database from
 *     brute-forcing a 4–6 digit PIN offline (SEC-20260721-020).
 */

import * as SQLite from 'expo-sqlite'
import * as SecureStore from 'expo-secure-store'
import type { KeyValueStore, SecureSecretStore } from './adapter'

const DB_NAME = 'lume.db'
const TABLE = 'vault'

let dbPromise: Promise<SQLite.SQLiteDatabase> | null = null

function getDb(): Promise<SQLite.SQLiteDatabase> {
  if (!dbPromise) {
    dbPromise = (async () => {
      const db = await SQLite.openDatabaseAsync(DB_NAME)
      await db.execAsync(`CREATE TABLE IF NOT EXISTS ${TABLE} (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);`)
      return db
    })()
  }
  return dbPromise
}

export const sqliteKeyValueStore: KeyValueStore = {
  async get<T>(key: string): Promise<T | undefined> {
    const db = await getDb()
    const row = await db.getFirstAsync<{ value: string }>(`SELECT value FROM ${TABLE} WHERE key = ?;`, key)
    if (!row) return undefined
    try {
      return JSON.parse(row.value) as T
    } catch {
      // A row that is not valid JSON is indistinguishable from a missing one to
      // the caller; the vault treats both as "no record" and fails closed.
      return undefined
    }
  },

  async set(key, value) {
    const db = await getDb()
    await db.runAsync(`INSERT OR REPLACE INTO ${TABLE} (key, value) VALUES (?, ?);`, key, JSON.stringify(value))
  },

  async del(key) {
    const db = await getDb()
    await db.runAsync(`DELETE FROM ${TABLE} WHERE key = ?;`, key)
  },

  async clear() {
    const db = await getDb()
    await db.runAsync(`DELETE FROM ${TABLE};`)
  },
}

export const keystoreSecretStore: SecureSecretStore = {
  async getSecret(key) {
    return SecureStore.getItemAsync(key)
  },
  async setSecret(key, value) {
    await SecureStore.setItemAsync(key, value, {
      // Available whenever the device has been unlocked once since boot; the
      // vault must be readable by a background sync, so this is deliberately not
      // WHEN_PASSCODE_SET_THIS_DEVICE_ONLY.
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    })
  },
  async deleteSecret(key) {
    await SecureStore.deleteItemAsync(key)
  },
}
