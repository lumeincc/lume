// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Opening and closing a session.
 *
 * Unlocking the vault is only half the job. The identity and master key must also
 * reach the in-memory key vault, because every authenticated request is signed
 * from there — without it registration succeeds and the very next call fails with
 * "no identity keys — cannot sign request".
 *
 * The ratchet sessions matter just as much: they live in memory while the app
 * runs, so without loading them at unlock (and writing them back as they advance)
 * every restart would drop the conversation state and both sides would stop being
 * able to decrypt each other.
 *
 * Kept separate from vault.ts so the storage layer stays free of the in-memory
 * key holder, and from registration.ts because this is the returning-user path.
 */

import {
  unlock,
  loadProfile,
  loadContacts,
  loadRatchetSessions,
  saveRatchetSessions,
  type UnlockResult,
  type AccountProfile,
  type Contact,
} from './vault'
import {
  vaultSetAuth,
  vaultClear,
  vaultSetSessions,
  vaultGetAllSessions,
  vaultGetMasterKey,
  vaultSubscribeSessionChanges,
} from './crypto/keyVault'
import { setCurrentPlatform } from './platform/current'
import type { Platform } from './platform/adapter'
import type { IdentityKeys } from './crypto/keys'

export type SessionResult =
  | { ok: true; identity: IdentityKeys; profile: AccountProfile | null; contacts: Contact[] }
  | { ok: false; reason: 'no-account' | 'wrong-pin' | 'corrupt' }

/** Unsubscribe for the session-persistence listener, so it dies with the session. */
let unsubscribeSessions: (() => void) | null = null

/**
 * Serialised chain of pending session writes.
 *
 * Persistence is triggered by a synchronous listener but the write itself is
 * async, so it must be tracked: closing the session zeroes the master key, and a
 * write still in flight would either use a zeroed key or be dropped entirely.
 * That is not theoretical — it silently lost the ratchet state whenever the app
 * closed right after sending, which breaks the conversation permanently for both
 * sides. Chaining also keeps concurrent writes from clobbering each other.
 */
let pendingWrite: Promise<void> = Promise.resolve()

/** Wait for every queued session write to land. Call before backgrounding. */
export function flushSessions(): Promise<void> {
  return pendingWrite
}

/**
 * Open the vault, load the keys for signing, and restore the ratchet state.
 *
 * The master key is handed to the key vault, which holds the reference and zeroes
 * it on `closeSession`; it is deliberately not zeroed here.
 */
export async function openSession(platform: Platform, pin: string): Promise<SessionResult> {
  // Let any write queued by a previous session land before repointing storage.
  // Without this, opening a session (a re-unlock, or switching account) discards
  // an in-flight write and the ratchet silently rolls back a step.
  await pendingWrite

  const res: UnlockResult = await unlock(platform, pin)
  if (!res.ok) return { ok: false, reason: res.reason }

  // Detach the previous session's listener BEFORE touching the vault.
  // `vaultSetSessions` notifies listeners, so a listener left attached here fires
  // while the vault already holds the NEW account's keys but still points at the
  // OLD platform — writing one account's sessions into the other's storage under
  // the wrong master key, which silently destroyed the sender's ratchet state.
  unsubscribeSessions?.()
  unsubscribeSessions = null

  // Vendored modules reach storage through the process-wide platform.
  setCurrentPlatform(platform)

  const profile = await loadProfile(platform, res.masterKey)
  const contacts = await loadContacts(platform, res.masterKey)
  const sessions = await loadRatchetSessions(platform, res.masterKey)

  vaultSetAuth(res.identity, res.masterKey)
  vaultSetSessions(sessions)

  // Persist whenever the ratchet advances. Doing it here rather than at each call
  // site means no code path can advance a session and forget to save it — the
  // failure that would silently break a conversation after a restart.
  pendingWrite = Promise.resolve()
  unsubscribeSessions = vaultSubscribeSessionChanges(() => {
    // Snapshot synchronously: by the time the queued write runs, the vault may
    // have advanced again, and the master key may be gone.
    const snapshot = vaultGetAllSessions()
    const masterKey = vaultGetMasterKey()
    pendingWrite = pendingWrite
      .then(() => saveRatchetSessions(platform, snapshot, masterKey))
      .catch(() => {
        // A failed write must not take down the app: the session is still correct
        // in memory, and the next advance will try again.
      })
  })

  return { ok: true, identity: res.identity, profile, contacts }
}

/**
 * Drop every live key from memory and stop persisting session changes.
 *
 * Awaits the queued writes first: clearing the vault zeroes the master key those
 * writes still need.
 */
export async function closeSession(): Promise<void> {
  unsubscribeSessions?.()
  unsubscribeSessions = null
  await pendingWrite
  vaultClear()
}
