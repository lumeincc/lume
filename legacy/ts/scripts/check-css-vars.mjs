#!/usr/bin/env node
/**
 * Design-token health check.
 *
 * A CSS custom property that is referenced but never defined does not error
 * anywhere — it silently resolves to nothing. That is how
 * `background: var(--surface-secondary)` shipped a panel with no background at
 * all, invisible to types, tests and lint alike.
 *
 * Reports two things:
 *   - undefined — referenced in source, defined in no stylesheet
 *   - unused    — defined, referenced nowhere
 *
 * Run: npm run check:css
 */

import { readFile, readdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative } from 'node:path'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const clientSrc = join(repoRoot, 'client', 'src')

/**
 * Tokens defined for consumers rather than for our own markup. Tailwind reads
 * the `@theme` block to generate utilities, so those names are used by class
 * names like `text-body`, never by a literal `var()`.
 */
const THEME_NAMESPACES = ['--color-', '--font-', '--text-', '--shadow-', '--radius-']

async function collectFiles(dir, test) {
  const entries = await readdir(dir, { withFileTypes: true })
  const found = await Promise.all(
    entries.map(async (entry) => {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        return entry.name === 'node_modules' ? [] : collectFiles(full, test)
      }
      return test(entry.name) ? [full] : []
    }),
  )
  return found.flat()
}

const styleFiles = await collectFiles(clientSrc, (name) => name.endsWith('.css'))
const sourceFiles = await collectFiles(clientSrc, (name) => /\.(tsx?|css)$/.test(name))

if (styleFiles.length === 0) {
  console.error('Found no stylesheets under client/src — check the path in scripts/check-css-vars.mjs.')
  process.exit(1)
}

/** name -> "file:line" of its definition */
const defined = new Map()
for (const file of styleFiles) {
  const css = await readFile(file, 'utf8')
  const declaration = /^\s*(--[a-z0-9-]+)\s*:/gim
  let match
  while ((match = declaration.exec(css)) !== null) {
    const name = match[1].toLowerCase()
    if (!defined.has(name)) {
      const line = css.slice(0, match.index).split('\n').length
      defined.set(name, `${relative(repoRoot, file)}:${line}`)
    }
  }
}

// Not every token comes from a stylesheet. `next/font` declares one in TS —
// `Space_Grotesk({ variable: "--font-space-grotesk" })` — and injects it through
// a className, so it is defined despite appearing nowhere in CSS. Reading the
// declaration covers any such font rather than allowlisting each one.
for (const file of sourceFiles) {
  if (file.endsWith('.css')) continue
  const source = await readFile(file, 'utf8')
  const injected = /\bvariable\s*:\s*["'](--[a-z0-9-]+)["']/gi
  let match
  while ((match = injected.exec(source)) !== null) {
    const name = match[1].toLowerCase()
    if (!defined.has(name)) {
      const line = source.slice(0, match.index).split('\n').length
      defined.set(name, `${relative(repoRoot, file)}:${line}`)
    }
  }
}

/** name -> first "file:line" that references it */
const referenced = new Map()
for (const file of sourceFiles) {
  const source = await readFile(file, 'utf8')
  const usage = /var\(\s*(--[a-z0-9-]+)/gi
  let match
  while ((match = usage.exec(source)) !== null) {
    const name = match[1].toLowerCase()
    if (!referenced.has(name)) {
      const line = source.slice(0, match.index).split('\n').length
      referenced.set(name, `${relative(repoRoot, file)}:${line}`)
    }
  }
}

const undefinedVars = [...referenced].filter(([name]) => !defined.has(name))
const unusedVars = [...defined].filter(
  ([name]) =>
    !referenced.has(name) && !THEME_NAMESPACES.some((prefix) => name.startsWith(prefix)),
)

let failed = false

if (undefinedVars.length > 0) {
  failed = true
  console.error(`\nReferenced but never defined (${undefinedVars.length}):`)
  for (const [name, where] of undefinedVars) console.error(`  ${name}  ${where}`)
  console.error('\nThese resolve to nothing at runtime — no error, just a missing style.')
}

if (unusedVars.length > 0) {
  console.error(`\nDefined but never referenced (${unusedVars.length}):`)
  for (const [name, where] of unusedVars) console.error(`  ${name}  ${where}`)
  console.error('\nNot fatal — remove them, or leave them if they are a deliberate part of the palette.')
}

if (failed) process.exit(1)

console.log(
  `Design tokens healthy — ${defined.size} defined, ${referenced.size} referenced, none missing.`,
)
