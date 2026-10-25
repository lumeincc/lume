#!/usr/bin/env node
/**
 * Dependency advisory gate with an allowlist.
 *
 * `npm audit` offers one lever — a severity threshold — and no way to say "we
 * read this one, here is why it stays". That leaves two bad options: fail on
 * everything, which makes the gate the first thing anyone disables, or gate on
 * nothing, which is what this repository did until it was cleaned up.
 *
 * So: fail on any advisory that is not written down in `audit-allowlist.json`
 * with a reason. New problems are loud. Known ones are a decision someone made
 * and can be read back.
 *
 * The allowlist is not a way to make a run go green. It exists because the
 * alternative — an override that silences the number — once broke the native
 * build here while reporting zero vulnerabilities, which is the failure mode
 * this whole approach is meant to prevent.
 *
 * Run: npm run audit:gate
 */

import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

/** `npm audit` exits non-zero when it finds anything, so failure is expected. */
function runAudit() {
  try {
    return execFileSync('npm', ['audit', '--json'], {
      cwd: root,
      encoding: 'utf8',
      shell: process.platform === 'win32',
      maxBuffer: 32 * 1024 * 1024,
    })
  } catch (error) {
    if (typeof error.stdout === 'string' && error.stdout.length > 0) return error.stdout
    throw error
  }
}

const report = JSON.parse(runAudit())
const allowlist = JSON.parse(readFileSync(join(root, 'audit-allowlist.json'), 'utf8'))

const allowedByPackage = new Map(allowlist.allowed.map(entry => [entry.package, entry]))

const unexpected = []
const accepted = []

for (const [name, vulnerability] of Object.entries(report.vulnerabilities ?? {})) {
  const entry = allowedByPackage.get(name)
  if (!entry) {
    unexpected.push({ name, severity: vulnerability.severity })
    continue
  }

  // An entry may name specific advisories, so a *new* problem in an
  // already-known package is still reported rather than covered by association.
  if (!entry.advisories.includes('*')) {
    const ids = vulnerability.via
      .filter(via => typeof via === 'object' && via.url)
      .map(via => via.url.split('/').pop())
    const unlisted = ids.filter(id => !entry.advisories.includes(id))
    if (unlisted.length > 0) {
      unexpected.push({ name, severity: vulnerability.severity, unlisted })
      continue
    }
  }

  accepted.push({ name, severity: vulnerability.severity, reason: entry.reason })
}

if (accepted.length > 0) {
  console.log(`Accepted, with reasons recorded in audit-allowlist.json:`)
  for (const item of accepted) {
    console.log(`  ${item.severity.padEnd(8)} ${item.name}`)
  }
  console.log('')
}

if (unexpected.length === 0) {
  console.log(`Advisory gate passed — ${accepted.length} known, 0 new.`)
  process.exit(0)
}

console.error('Advisory gate FAILED — these are not in the allowlist:\n')
for (const item of unexpected) {
  const extra = item.unlisted ? ` (new advisories: ${item.unlisted.join(', ')})` : ''
  console.error(`  ${item.severity.padEnd(8)} ${item.name}${extra}`)
}
console.error(
  '\nFix them, or add an entry to audit-allowlist.json with a reason, why it is' +
    '\nnot fixed, and what the real fix is. Do not add one just to go green.'
)
process.exit(1)
