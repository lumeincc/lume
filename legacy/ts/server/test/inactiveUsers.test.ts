// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Inactive accounts are reclaimed and their usernames released.
 *
 * The `users` table was the only one with no bound. Deleting the row is safe by
 * design — it is a cache, and a client re-binds its existing identity silently
 * on the next unlock — but it releases the username, which someone else can
 * then take. That is why this is an owner decision and why it is tested rather
 * than trusted: an irreversible delete driven by a timestamp deserves proof
 * that it deletes the right rows and, more importantly, leaves the others alone.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import Database from 'better-sqlite3'
import nacl from 'tweetnacl'
import { encodeBase64 } from 'tweetnacl-util'
import { rmSync } from 'fs'

/**
 * A file-backed database, not `:memory:`.
 *
 * The ages these tests need cannot be produced through the public API — it only
 * ever writes `last_seen` as "now" — and widening `database.ts` with a raw
 * handle purely for tests would enlarge the surface of a security-sensitive
 * module. A second connection to the same file writes the timestamps instead,
 * which `:memory:` cannot do because each connection gets its own database.
 */
const tempDir = vi.hoisted(() => {
  const dir = require('fs').mkdtempSync(require('path').join(require('os').tmpdir(), 'lume-inactive-'))
  process.env.DB_PATH = require('path').join(dir, 'test.db')
  process.env.WS_JWT_SECRET = 'x'.repeat(40)
  return dir
})

import database from '../src/db/database'

const raw = new Database(process.env.DB_PATH as string)

const DAY = 24 * 60 * 60
const now = Math.floor(Date.now() / 1000)

function makeUser(username: string, lastSeenAgeDays: number | null, createdAgeDays: number): string {
  const id = crypto.randomUUID()
  const idKey = nacl.sign.keyPair()
  const spk = nacl.sign.keyPair()
  database.createUser(
    id,
    username,
    encodeBase64(idKey.publicKey),
    encodeBase64(idKey.publicKey),
    encodeBase64(spk.publicKey),
    encodeBase64(nacl.sign.detached(spk.publicKey, idKey.secretKey))
  )
  // The public API only ever sets `last_seen` to "now", so the ages this test
  // needs are written directly.
  raw
    .prepare('UPDATE users SET last_seen = ?, created_at = ? WHERE id = ?')
    .run(
      lastSeenAgeDays === null ? null : now - lastSeenAgeDays * DAY,
      now - createdAgeDays * DAY,
      id
    )
  return id
}

beforeAll(() => {
  raw.prepare('DELETE FROM users').run()
})

afterAll(() => {
  raw.close()
  try {
    rmSync(tempDir, { recursive: true, force: true })
  } catch {
    // The module under test opens its own long-lived connection and never
    // closes it — correct for a server process, and on Windows it makes the
    // file undeletable while this process lives. The directory sits under the
    // OS temp path and is collected there; failing the suite over tidiness
    // would be reporting a problem that does not exist.
  }
})

describe('purgeInactiveUsers', () => {
  it('removes an account silent past the cutoff and frees its username', () => {
    makeUser('stale_one', 400, 500)
    const cutoff = now - 365 * DAY

    const { users } = database.purgeInactiveUsers(cutoff, 100)
    expect(users.map(u => u.username)).toContain('stale_one')

    // The point of the exercise: the name is available again.
    expect(database.getUserByUsername('stale_one')).toBeFalsy()
  })

  it('leaves an active account alone', () => {
    makeUser('active_one', 3, 400)
    const cutoff = now - 365 * DAY

    const { users } = database.purgeInactiveUsers(cutoff, 100)
    expect(users.map(u => u.username)).not.toContain('active_one')
    expect(database.getUserByUsername('active_one')).toBeTruthy()
  })

  it('counts an account that was registered and never used', () => {
    // `last_seen` stays null until a first authenticated action. Matching on it
    // alone would exempt exactly the accounts most worth reclaiming — registered
    // in bulk, never touched again.
    makeUser('never_used', null, 400)
    const { users } = database.purgeInactiveUsers(now - 365 * DAY, 100)
    expect(users.map(u => u.username)).toContain('never_used')
  })

  it('does not reclaim a fresh account that has never been used', () => {
    makeUser('registered_today', null, 0)
    const { users } = database.purgeInactiveUsers(now - 365 * DAY, 100)
    expect(users.map(u => u.username)).not.toContain('registered_today')
    expect(database.getUserByUsername('registered_today')).toBeTruthy()
  })

  it('honours the batch limit rather than deleting everything at once', () => {
    for (let i = 0; i < 5; i++) makeUser(`batch_${i}`, 400, 500)
    const first = database.purgeInactiveUsers(now - 365 * DAY, 2)
    expect(first.users).toHaveLength(2)

    const second = database.purgeInactiveUsers(now - 365 * DAY, 2)
    expect(second.users).toHaveLength(2)

    const third = database.purgeInactiveUsers(now - 365 * DAY, 10)
    expect(third.users).toHaveLength(1)
  })

  it('takes the oldest first, so a bounded pass makes progress at the far end', () => {
    makeUser('older', 900, 900)
    makeUser('newer', 400, 400)
    const { users } = database.purgeInactiveUsers(now - 365 * DAY, 1)
    expect(users[0]?.username).toBe('older')
  })

  it('reports nothing when nothing qualifies', () => {
    // A cutoff older than any row here, rather than relying on earlier tests
    // having emptied the table — which they had not, and the first version of
    // this test failed for that reason rather than for a real one.
    const { users, fileIds } = database.purgeInactiveUsers(now - 10_000 * DAY, 100)
    expect(users).toEqual([])
    expect(fileIds).toEqual([])
  })
})
