// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Unlock-secret policy.
 *
 * A 4–6 digit numeric PIN is only ~13–20 bits of entropy, so the whole at-rest
 * store — whose master key is derived from it — is brute-forceable offline
 * regardless of the 600k-iteration KDF. Requiring at least 8 characters and
 * allowing non-numeric secrets lifts a chosen passphrase to ~47+ bits, which
 * with PBKDF2-600k puts offline brute-force out of reach.
 *
 * Owner decision (Bogdan): passphrase, min 8, alphanumeric allowed, KDF
 * unchanged. SEC-20260721-020.
 */
export const MIN_PIN_LENGTH = 8;
export const MAX_PIN_LENGTH = 128;

/** True when a secret meets the minimum length policy. */
export function isPinLongEnough(pin: string): boolean {
  return pin.length >= MIN_PIN_LENGTH;
}
