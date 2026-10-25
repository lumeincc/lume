#!/usr/bin/env node
/**
 * Catalogue health check.
 *
 * A string catalogue rots quietly: keys outlive the component that used them,
 * and a new locale silently misses entries that only `en` has. TypeScript
 * catches a misspelled key at the call site but says nothing about either of
 * those, because both are still perfectly valid objects.
 *
 * Reports three things:
 *   - unused  — in the catalogue, referenced by no source file
 *   - missing — referenced in source, absent from the catalogue
 *   - drift   — present in `en`, absent from another locale
 *
 * Run: npm run check:i18n
 */

import { readFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative } from 'node:path'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const srcRoot = join(repoRoot, 'client', 'src')
const i18nDir = join(srcRoot, 'lib', 'i18n')

/** Keys a linter cannot see used — referenced dynamically or by a variable. */
const ALLOW_UNUSED = new Set([])

async function collectSourceFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  const files = await Promise.all(
    entries.map(async (entry) => {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (entry.name === '__tests__' || entry.name === 'node_modules') return []
        return collectSourceFiles(full)
      }
      return /\.tsx?$/.test(entry.name) ? [full] : []
    }),
  )
  return files.flat()
}

/**
 * Reads the keys of a catalogue module without importing it — the file is TSX-
 * adjacent TypeScript, and spawning a compiler to list object keys is more
 * machinery than the job needs.
 */
async function readCatalogueKeys(file) {
  const source = await readFile(file, 'utf8')
  const keys = new Map()
  const entry = /^\s{2}"([^"]+)":/gm
  let match
  while ((match = entry.exec(source)) !== null) {
    const key = match[1]
    const line = source.slice(0, match.index).split('\n').length
    if (keys.has(key)) {
      console.error(`Duplicate key "${key}" in ${relative(repoRoot, file)} (line ${line})`)
      process.exitCode = 1
    }
    keys.set(key, line)
  }
  return keys
}

const enKeys = await readCatalogueKeys(join(i18nDir, 'en.ts'))
if (enKeys.size === 0) {
  console.error('Read no keys from en.ts — the catalogue format probably changed.')
  console.error('Update the entry pattern in scripts/check-i18n.mjs.')
  process.exit(1)
}

const sourceFiles = (await collectSourceFiles(srcRoot)).filter(
  (file) => !file.startsWith(i18nDir),
)

const referenced = new Set()
const unknown = new Map()

for (const file of sourceFiles) {
  const source = await readFile(file, 'utf8')

  // A direct t("key") call is the common case, and the only one that can name a
  // key the catalogue does not have.
  const call = /\bt\(\s*["']([^"']+)["']/g
  let match
  while ((match = call.exec(source)) !== null) {
    const key = match[1]
    referenced.add(key)
    if (!enKeys.has(key)) {
      const line = source.slice(0, match.index).split('\n').length
      unknown.set(key, `${relative(repoRoot, file)}:${line}`)
    }
  }

  // Keys also reach `t` indirectly, through a lookup table — StatusBanner maps
  // a WebSocket status to a key that way. Counting any quoted occurrence keeps
  // that pattern from being reported as dead. It can call a key used when it is
  // only named in a comment; that is the cheaper error, since the alternative
  // is an allowlist that grows until the check means nothing.
  const literal = /["']([a-z][a-zA-Z]*(?:\.[a-zA-Z]+)+)["']/g
  while ((match = literal.exec(source)) !== null) {
    if (enKeys.has(match[1])) referenced.add(match[1])
  }
}

const unused = [...enKeys.keys()].filter((key) => !referenced.has(key) && !ALLOW_UNUSED.has(key))

// Locale drift: every catalogue other than en must cover what en defines.
const localeFiles = (await readdir(i18nDir)).filter(
  (name) => /^[a-z]{2}(-[A-Z]{2})?\.ts$/.test(name) && name !== 'en.ts',
)

const drift = []
for (const name of localeFiles) {
  const keys = await readCatalogueKeys(join(i18nDir, name))
  const missing = [...enKeys.keys()].filter((key) => !keys.has(key))
  const extra = [...keys.keys()].filter((key) => !enKeys.has(key))
  if (missing.length > 0 || extra.length > 0) drift.push({ name, missing, extra })
}

let failed = false

if (unknown.size > 0) {
  failed = true
  console.error(`\nMissing from the catalogue (${unknown.size}):`)
  for (const [key, where] of unknown) console.error(`  "${key}"  ${where}`)
}

if (unused.length > 0) {
  failed = true
  console.error(`\nUnused keys (${unused.length}):`)
  for (const key of unused) console.error(`  "${key}"  en.ts:${enKeys.get(key)}`)
  console.error('\nRemove them, or add to ALLOW_UNUSED with a reason if referenced dynamically.')
}

for (const { name, missing, extra } of drift) {
  failed = true
  if (missing.length > 0) {
    console.error(`\n${name} is missing ${missing.length} key(s) that en.ts defines:`)
    for (const key of missing) console.error(`  "${key}"`)
  }
  if (extra.length > 0) {
    console.error(`\n${name} defines ${extra.length} key(s) that en.ts does not:`)
    for (const key of extra) console.error(`  "${key}"`)
  }
}

if (failed || process.exitCode === 1) process.exit(1)

console.log(
  `Catalogue healthy — ${enKeys.size} keys, all referenced` +
    (localeFiles.length > 0 ? `, ${localeFiles.length} locale(s) in sync.` : '.'),
)
