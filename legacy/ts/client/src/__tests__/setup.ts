// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Vitest global setup
 * Provides Web Crypto API and other browser globals for all test environments.
 */

import { webcrypto } from 'crypto';

// In Node environment, globalThis.crypto may be missing in Node < 19.
// Provide it unconditionally — harmless if already defined.
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: false,
    configurable: true,
  });
}
