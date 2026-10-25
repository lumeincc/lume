#!/usr/bin/env node
/**
 * Remove Turbopack's persistent development cache.
 *
 * On 2026-08-11 that cache went bad and cost half a day. It had memoised a
 * failed resolution of the Next.js package for one route; every visit to
 * `/chats` then panicked the dev server, Fast Refresh gave up and reloaded the
 * document, the in-memory key vault died with the page, and the app redirected
 * to `/unlock` — exactly as it should. Two end-to-end specs failed, and they
 * failed *as if the product had dropped a live session*. Nothing pointed at the
 * bundler. CI stayed green, because a fresh checkout has no persistent cache.
 *
 * So this runs before the end-to-end suite: the tests should start from the
 * same blank state CI has, rather than inherit whatever a week of local
 * development left behind. It costs a recompile — well under a minute against a
 * suite that takes ten — and it makes a whole class of failure impossible
 * instead of merely rare.
 *
 * **Delete it, never rename it.** `.next` → `.next-bak` was tried: the backup is
 * no longer covered by `.gitignore`, Tailwind then scans the binary build output
 * and emits mangled utilities, and the dev server dies on its start timeout.
 * Move it outside the repository if you want to keep a copy.
 *
 * If this class of failure reappears, its signature in Playwright's output is:
 *   [WebServer] FATAL: An unexpected Turbopack error occurred
 *
 * Run: npm run clean
 */

import { rm, stat } from 'node:fs/promises'
import { join } from 'node:path'

const TARGET = join('client', '.next', 'dev', 'cache')

const before = await stat(TARGET).catch(() => null)
if (!before) {
  console.log('Dev cache already absent — nothing to clean.')
  process.exit(0)
}

// The build output in `client/.next` is deliberately left alone: only the dev
// server's cache is at issue, and removing the rest would force a full
// production rebuild that has nothing to do with this.
await rm(TARGET, { recursive: true, force: true })
console.log('Removed Turbopack dev cache — the end-to-end run starts cold, like CI.')
