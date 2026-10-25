#!/usr/bin/env node
/**
 * Secret scan, when a scanner is available.
 *
 * CI pins its own gitleaks binary; a developer machine may or may not have one.
 * The important part is what happens when it does not: this says so and exits
 * non-zero-free, rather than printing nothing and letting a green run imply the
 * history was checked. "Not checked" is its own outcome and has to look like
 * one, or the gate quietly becomes decoration.
 *
 * Install once and it starts working:
 *   winget install gitleaks   ·   brew install gitleaks   ·   apt install gitleaks
 *
 * Run: npm run check:secrets
 */

import { execFileSync, spawnSync } from 'node:child_process'

const isWindows = process.platform === 'win32'

function hasGitleaks() {
  const probe = spawnSync('gitleaks', ['version'], { shell: isWindows, encoding: 'utf8' })
  return probe.status === 0
}

if (!hasGitleaks()) {
  console.log('Secret scan SKIPPED — gitleaks is not installed on this machine.')
  console.log('  The history was not checked here. CI does check it.')
  console.log('  To check locally: winget install gitleaks (or brew/apt).')
  // Deliberately not a failure: a missing local tool is not a broken repository,
  // and making it one would train people to skip the whole gate.
  process.exit(0)
}

try {
  // --redact so a finding never prints the secret into a terminal or a log.
  execFileSync('gitleaks', ['git', '--redact', '-v', '--no-banner', '--log-opts=--all', '.'], {
    stdio: 'inherit',
    shell: isWindows,
  })
  console.log('Secret scan passed — nothing unexpected in the history.')
} catch {
  console.error('\nSecret scan FAILED. Anything reported above is in the git history,')
  console.error('which means removing it from the working tree is not enough.')
  console.error('If it is a false positive, add its fingerprint to .gitleaksignore')
  console.error('with a reason — never disable the rule.')
  process.exit(1)
}
