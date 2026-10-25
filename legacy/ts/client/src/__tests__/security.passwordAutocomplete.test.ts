// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * SEC-20260805-002 — no password field may be offered to a password manager.
 *
 * LUME has no login password. Every `type="password"` field in the app holds a
 * local secret: the passphrase that derives the at-rest master key, or a
 * hidden-chat PIN. A browser password manager stores those beside the encrypted
 * store they protect and usually syncs them to a vendor cloud, which is the one
 * thing this product promises does not happen.
 *
 * The finding was reported against the unlock screen. Fixing only that screen
 * would have left thirteen other password inputs untouched, so the default now
 * lives in `components/ui/Input.tsx` and the raw `<input>` call sites carry it
 * explicitly.
 *
 * This suite scans source rather than rendering, because the regression it
 * guards against is *a new field being added without it* — which no render test
 * of the existing screens can see.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

// Resolved from this file, not from `process.cwd()`: the working directory
// depends on how vitest was invoked, and a scanner pointed at the wrong
// directory finds nothing — which is the one way a guard like this fails
// silently.
const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Password fields known at the time of the fix. Asserting a floor keeps the
 * suite from passing vacuously if the scan ever stops matching anything.
 */
const KNOWN_FIELD_COUNT = 15;

function tsxFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === '__tests__') continue;
      out.push(...tsxFiles(full));
    } else if (entry.name.endsWith('.tsx')) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Source of the JSX opening tag containing `index`.
 *
 * Attributes routinely contain `>` (`onKeyDown={(e) => …}`) and `<`, so neither
 * end can be found by searching for a bare character: the forward scan tracks
 * brace depth, quotes and comments, and stops at the first `>` outside all of
 * them. Comments matter — a `//` note between attributes mentioning a tag would
 * otherwise cut the element short and hide the attributes after it, which is
 * exactly how this scanner first reported a false offender.
 */
function enclosingTag(source: string, index: number): { name: string; text: string } | null {
  let start = -1;
  for (let i = index; i >= 0; i--) {
    if (source[i] === '<' && /[A-Za-z]/.test(source[i + 1] ?? '')) {
      start = i;
      break;
    }
  }
  if (start === -1) return null;

  let depth = 0;
  let quote: string | null = null;
  for (let i = start + 1; i < source.length; i++) {
    const c = source[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    // Comments are skipped, not scanned. Checked inside the `!quote` branch so a
    // "https://…" in an attribute value is not mistaken for one.
    if (c === '/' && source[i + 1] === '/') {
      const nl = source.indexOf('\n', i);
      if (nl === -1) return null;
      i = nl;
      continue;
    }
    if (c === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      if (end === -1) return null;
      i = end + 1;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') quote = c;
    else if (c === '{') depth++;
    else if (c === '}') depth--;
    else if (c === '>' && depth === 0) {
      const text = source.slice(start, i + 1);
      const name = /^<([A-Za-z][\w.]*)/.exec(text)?.[1] ?? '';
      return { name, text };
    }
  }
  return null;
}

interface Field {
  file: string;
  line: number;
  tag: string;
  text: string;
}

function passwordFields(): Field[] {
  const found: Field[] = [];
  for (const file of tsxFiles(SRC)) {
    const source = readFileSync(file, 'utf8');
    const pattern = /type="password"/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(source)) !== null) {
      const tag = enclosingTag(source, match.index);
      if (!tag) continue;
      found.push({
        file: path.relative(SRC, file).replace(/\\/g, '/'),
        line: source.slice(0, match.index).split('\n').length,
        tag: tag.name,
        text: tag.text,
      });
    }
  }
  return found;
}

describe('password fields are never offered to a password manager', () => {
  it('finds the password fields at all', () => {
    // Guards the guard: a scan that silently matches nothing would report green
    // forever while every field regressed.
    expect(existsSync(SRC)).toBe(true);
    expect(passwordFields().length).toBeGreaterThanOrEqual(KNOWN_FIELD_COUNT);
  });

  it('every one of them opts out', () => {
    const offenders = passwordFields().filter((field) => {
      // <Input> gets `autoComplete="new-password"` from the shared component.
      if (field.tag === 'Input') return false;
      return !/autoComplete="new-password"/.test(field.text);
    });

    expect(
      offenders.map((o) => `${o.file}:${o.line} <${o.tag}>`),
      'raw password inputs missing autoComplete="new-password"',
    ).toEqual([]);
  });

  it('none of them settles for autoComplete="off"', () => {
    // Chromium ignores `off` on password fields and offers to save regardless,
    // so `off` reads as handled while behaving as unhandled.
    const weak = passwordFields().filter((field) => /autoComplete="off"/.test(field.text));
    expect(weak.map((o) => `${o.file}:${o.line}`)).toEqual([]);
  });
});
