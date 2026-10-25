// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Compatibility shim presenting the web client's storage API.
 *
 * The vendored modules (keyVault, spkRotation, …) were written against the web's
 * crypto/storage.ts, where persistence is an implicit global (IndexedDB) and the
 * functions take only a master key. The mobile vault instead takes an explicit
 * Platform, so tests can drive isolated instances.
 *
 * Rather than editing the vendored files — which would break the byte-identity
 * that the shared test vectors rely on — this module re-exposes the web's exact
 * surface on top of src/vault.ts, resolving the platform from the process-wide
 * one set at startup. Vendored code keeps importing `./storage` and never learns
 * the difference.
 */

import {
  loadPreKeyMaterial as vaultLoadPreKeyMaterial,
  savePreKeyMaterial as vaultSavePreKeyMaterial,
  type LocalPreKeyMaterial,
} from '../vault'
import { getCurrentPlatform } from '../platform/current'
import type { KeyPair } from './keys'

export type { LocalPreKeyMaterial }

// ── Master key cache ─────────────────────────────────────────────────────────

let cachedMasterKey: Uint8Array | null = null

export function setCachedMasterKey(key: Uint8Array | null): void {
  cachedMasterKey = key
}

export function getCachedMasterKey(): Uint8Array | null {
  return cachedMasterKey
}

export function clearCachedMasterKey(): void {
  if (cachedMasterKey) cachedMasterKey.fill(0)
  cachedMasterKey = null
}

// ── Prekey material, in the web's shape ──────────────────────────────────────

export async function loadPreKeyMaterial(masterKey: Uint8Array): Promise<LocalPreKeyMaterial | null> {
  return vaultLoadPreKeyMaterial(getCurrentPlatform(), masterKey)
}

export async function savePreKeyMaterial(
  material: LocalPreKeyMaterial,
  masterKey: Uint8Array
): Promise<void> {
  return vaultSavePreKeyMaterial(getCurrentPlatform(), material, masterKey)
}

/**
 * Look up the secret half of a one-time prekey the sender addressed. Returns null
 * when it is not held — which is a real condition, not an error: the key may
 * already have been consumed by an earlier handshake.
 */
export async function findOneTimePreKey(
  publicKey: string,
  masterKey: Uint8Array
): Promise<KeyPair | null> {
  const material = await loadPreKeyMaterial(masterKey)
  if (!material) return null
  return material.oneTimePreKeys.find(k => k.publicKey === publicKey) ?? null
}

/**
 * Consume a one-time prekey: X3DH's forward secrecy depends on each one being
 * used at most once, so it is removed as soon as a handshake has used it.
 */
export async function deleteOneTimePreKey(publicKey: string, masterKey: Uint8Array): Promise<void> {
  const material = await loadPreKeyMaterial(masterKey)
  if (!material) return
  const remaining = material.oneTimePreKeys.filter(k => k.publicKey !== publicKey)
  if (remaining.length === material.oneTimePreKeys.length) return
  await savePreKeyMaterial({ ...material, oneTimePreKeys: remaining }, masterKey)
}
