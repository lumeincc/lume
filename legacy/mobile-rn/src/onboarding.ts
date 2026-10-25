// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { createAccountWithMnemonic, recoverIdentityFromMnemonic } from './crypto/mnemonic'
import { deriveMasterKey } from './identity'
import { deriveMasterKey as deriveVaultMasterKey, saveIdentityKeys, savePinToken } from './vault'
import type { IdentityKeys } from './crypto/keys'
import type { Platform, PlatformCrypto } from './platform/adapter'

export interface NewIdentity {
  /** Show once during setup, then wipe from memory. Never leaves the device. */
  mnemonic: string
  /** Ed25519 (signing) + X25519 (exchange). Only the public halves are published. */
  identity: IdentityKeys
  /** Stored next to the encrypted vault so the master key can be re-derived from the PIN. */
  salt: Uint8Array
  /** Length of the derived master key — proof the KDF ran, without exposing the key. */
  masterKeyLength: number
}

/**
 * Create a fresh LUME identity on device: a BIP39 mnemonic → Ed25519/X25519
 * identity (deterministic — the same construction as the web client), plus a
 * PIN-derived master key that will seal the key material at rest.
 *
 * This is the crypto spine of onboarding. Persistence (writing the encrypted
 * vault) and registration (publishing the public keys) are layered on top by the
 * storage adapter and the API client — both reused from the web client.
 */
export async function createIdentity(platform: PlatformCrypto, pin: string): Promise<NewIdentity> {
  const { mnemonic, identity } = await createAccountWithMnemonic()
  const salt = platform.randomBytes(16)
  const masterKey = await deriveMasterKey(platform, pin, salt)
  const masterKeyLength = masterKey.length
  // The vault layer owns the master key's real lifecycle; do not keep it here.
  masterKey.fill(0)
  return { mnemonic, identity, salt, masterKeyLength }
}

/** Recover an existing identity from its mnemonic (deterministic). */
export async function recoverIdentity(mnemonic: string): Promise<IdentityKeys> {
  return recoverIdentityFromMnemonic(mnemonic)
}

export interface CreatedAccount {
  /** Show once, have the user write it down, then drop it. */
  mnemonic: string
  identity: IdentityKeys
}

/**
 * Full setup: mint an identity and seal it into the vault under the PIN, so the
 * next launch goes to unlock instead of setup. The master key is zeroed here —
 * callers that need it should `unlock` and own its lifetime.
 */
export async function createAccount(platform: Platform, pin: string): Promise<CreatedAccount> {
  const { mnemonic, identity } = await createAccountWithMnemonic()
  const masterKey = await deriveVaultMasterKey(platform, pin)
  try {
    await saveIdentityKeys(platform, identity, masterKey)
    await savePinToken(platform, masterKey)
  } finally {
    masterKey.fill(0)
  }
  return { mnemonic, identity }
}

/**
 * Restore an account from its mnemonic on a new device (or after a wipe) and seal
 * it under a fresh PIN. Deterministic: the recovered identity is the same one,
 * which is why losing the local vault is survivable.
 */
export async function restoreAccount(
  platform: Platform,
  mnemonic: string,
  pin: string
): Promise<IdentityKeys> {
  const identity = await recoverIdentityFromMnemonic(mnemonic)
  const masterKey = await deriveVaultMasterKey(platform, pin)
  try {
    await saveIdentityKeys(platform, identity, masterKey)
    await savePinToken(platform, masterKey)
  } finally {
    masterKey.fill(0)
  }
  return identity
}
