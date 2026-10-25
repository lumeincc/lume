// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The one platform this process runs on.
 *
 * The vendored modules were written against the web client, where storage is an
 * implicit global (IndexedDB) and functions take only a master key. The mobile
 * port passes a Platform explicitly so tests can run several isolated instances
 * — but there is exactly one at runtime, so this holds it and lets the
 * compatibility shim in crypto/storage.ts present the web's API surface
 * unchanged. That is what keeps vendored files byte-identical with the web.
 *
 * Set once at startup (or per test).
 */

import type { Platform } from './adapter'

let current: Platform | null = null

export function setCurrentPlatform(platform: Platform): void {
  current = platform
}

export function getCurrentPlatform(): Platform {
  if (!current) {
    throw new Error('Platform not set — call setCurrentPlatform() before using storage')
  }
  return current
}

export function hasCurrentPlatform(): boolean {
  return current !== null
}
