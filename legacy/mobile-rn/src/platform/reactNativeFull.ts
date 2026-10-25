// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The complete device platform: pure-JS KDF + SQLite vault + keystore secret.
 *
 * Kept separate from reactNative.ts on purpose. This module pulls in native
 * modules (expo-sqlite, expo-secure-store) and therefore cannot be imported
 * under Node, while reactNative.ts stays pure so the PBKDF2 parity test can
 * import it and prove the device KDF matches the web client's.
 */

import type { Platform } from './adapter'
import { devicePlatformCrypto } from './nativeCrypto'
import { sqliteKeyValueStore, keystoreSecretStore } from './reactNativeStorage'

export const devicePlatform: Platform = {
  // Native PBKDF2 with a pure-JS fallback; see nativeCrypto.ts.
  crypto: devicePlatformCrypto,
  kv: sqliteKeyValueStore,
  secure: keystoreSecretStore,
}
