// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The platform seam. Everything the crypto core needs from the OS that differs
 * between web, Node (tests) and React Native goes through this interface, so the
 * vendored core itself stays byte-identical across platforms.
 *
 * Implementations:
 *   - Node (src/platform/node.ts)        — node:crypto + in-memory stores; used by the tests.
 *   - RN   (src/platform/reactNative.ts) — @noble/hashes pbkdf2, react-native-get-random-values,
 *                                          expo-sqlite, expo-secure-store.
 */
export interface PlatformCrypto {
  /**
   * PBKDF2-SHA256 → raw derived key bytes. Pure JS on device (~1s for 600k),
   * which is why key derivation is a one-time setup/unlock cost, not per-message.
   */
  pbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number, keyLenBytes: number): Promise<Uint8Array>

  /** Cryptographically-secure random bytes from the OS CSPRNG. */
  randomBytes(length: number): Uint8Array
}

/**
 * Persistence for the encrypted vault — the seam that replaces `idb-keyval` on
 * mobile. Values are opaque to this layer: everything sensitive is already
 * sealed with the master key before it gets here, so the backing store only ever
 * holds ciphertext.
 */
export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>
  set(key: string, value: unknown): Promise<void>
  del(key: string): Promise<void>
  /** Wipes every key this store owns — backs panic-wipe and account deletion. */
  clear(): Promise<void>
}

/**
 * Hardware-backed secret storage (Android Keystore / iOS Keychain).
 *
 * This exists to lift the at-rest ceiling that the web client cannot escape: on
 * the web the vault is sealed by a key derived from the PIN alone, so a 4–6 digit
 * PIN caps the whole store at 13–20 bits and an attacker holding the stored blob
 * can brute-force it offline (SEC-20260721-020). Here a high-entropy device
 * secret, held by the OS keystore and never written to app storage, is mixed into
 * the KDF — so the stored blob alone is not enough to mount that attack.
 */
export interface SecureSecretStore {
  getSecret(key: string): Promise<string | null>
  setSecret(key: string, value: string): Promise<void>
  deleteSecret(key: string): Promise<void>
}

/** Everything the storage layer needs from the platform, in one bundle. */
export interface Platform {
  crypto: PlatformCrypto
  kv: KeyValueStore
  secure: SecureSecretStore
}
