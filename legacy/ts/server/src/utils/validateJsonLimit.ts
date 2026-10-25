// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Startup validation for JSON_LIMIT (SEC-20260721-007).
 *
 * `express.json({ limit })` hands the value to `bytes.parse`, which returns
 * `null` for anything it does not understand — and body-parser before 1.20.6
 * treats that as "no limit" rather than as an error. The failure is therefore
 * silent and inverted: a typo does not shrink the ceiling or throw, it removes
 * it. `JSON_LIMIT=8 mb` with a space is enough.
 *
 * That matters more here than it would elsewhere, because the `verify` hook
 * materialises every accepted body as a UTF-8 string on `rawBody`, and body
 * parsing runs before `requireSignature` — so an unauthenticated request would
 * be the one holding the memory.
 *
 * Upgrading past the advisory removes the silent-disable behaviour. This exists
 * because the pattern it depends on — trusting an unvalidated environment
 * variable — would otherwise still be here for the next dependency to meet.
 * Same discipline as `validateWsJwtSecret`: refuse to boot rather than run
 * misconfigured.
 */

export type JsonLimitValidation = { ok: true; value: string } | { ok: false; reason: string }

/**
 * Units, as a Map rather than an object literal so the lookup is not a dynamic
 * property read on attacker-influenced input.
 */
const UNIT_BYTES = new Map<string, number>([
  ['', 1],
  ['b', 1],
  ['kb', 1024],
  ['mb', 1024 * 1024],
  ['gb', 1024 * 1024 * 1024],
])

/**
 * Splits "8mb" into "8" and "mb" by scanning, deliberately without a regex.
 *
 * The obvious pattern here nests quantifiers (`\d+(?:\.\d+)?`), which
 * `security/detect-unsafe-regex` rejects — correctly as policy, even though this
 * particular one is not exploitable. Since the input is a startup environment
 * variable, the cheapest answer is to remove the regex rather than argue with
 * the rule: a scan has no backtracking surface at all.
 */
function splitAmountAndUnit(input: string): { amount: string; unit: string } {
  const ZERO = 48
  const NINE = 57
  const DOT = 46

  // charCodeAt rather than input[i]: it returns a number instead of
  // `string | undefined`, which keeps both noUncheckedIndexedAccess and the
  // object-injection rule satisfied without an assertion or a disable.
  let i = 0
  while (i < input.length) {
    const code = input.charCodeAt(i)
    if ((code >= ZERO && code <= NINE) || code === DOT) i += 1
    else break
  }

  return { amount: input.slice(0, i), unit: input.slice(i).trim().toLowerCase() }
}

/**
 * A ceiling on the ceiling. Anything this large is a misconfiguration rather
 * than a deliberate choice — the point of the limit is to bound memory per
 * request, and `rawBody` doubles whatever is accepted.
 */
const MAX_REASONABLE_BYTES = 64 * 1024 * 1024

export function validateJsonLimit(
  raw: string | undefined | null,
  fallback = '8mb'
): JsonLimitValidation {
  // Unset is fine — the default applies. Present-but-empty is not: it means
  // someone set it and got it wrong, which is exactly the case worth catching.
  if (raw === undefined || raw === null) {
    return { ok: true, value: fallback }
  }

  const trimmed = raw.trim()
  if (trimmed === '') {
    return { ok: false, reason: 'JSON_LIMIT is set but empty' }
  }

  const { amount: amountText, unit } = splitAmountAndUnit(trimmed)
  const multiplier = UNIT_BYTES.get(unit)

  // `Number('')` is 0 and `Number('1.2.3')` is NaN, so both are caught below;
  // an unknown unit ("mib", "megabytes") has no multiplier and is caught here.
  if (amountText === '' || multiplier === undefined) {
    return {
      ok: false,
      reason: `JSON_LIMIT="${raw}" is not a size bytes can parse (expected e.g. "8mb", "512kb", "1048576")`,
    }
  }

  const bytes = Number(amountText) * multiplier

  if (!Number.isFinite(bytes) || bytes <= 0) {
    return { ok: false, reason: `JSON_LIMIT="${raw}" resolves to a non-positive size` }
  }

  if (bytes > MAX_REASONABLE_BYTES) {
    return {
      ok: false,
      reason: `JSON_LIMIT="${raw}" exceeds the ${MAX_REASONABLE_BYTES / (1024 * 1024)}MB ceiling`,
    }
  }

  // Return the trimmed form rather than the raw one: a trailing space is
  // harmless to us but is precisely what bytes.parse rejects.
  return { ok: true, value: trimmed }
}
