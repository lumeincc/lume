// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import type { PlatformCrypto } from './adapter'
import { pbkdf2 } from '@noble/hashes/pbkdf2.js'
import { sha256 } from '@noble/hashes/sha2.js'

/**
 * React Native platform seam.
 *
 * PBKDF2 runs in PURE JS (@noble/hashes) — no native crypto module. This was a
 * deliberate choice after react-native-quick-crypto (a JSI native module) proved
 * fragile on the RN 0.76 old architecture and crashed the app at import time.
 * 600k iterations is ~1–2s on a phone: fine for a one-time identity setup. If the
 * unlock delay ever matters, swap in a native PBKDF2 behind this same seam.
 *
 * Randomness comes from the OS CSPRNG via react-native-get-random-values, which
 * is imported for its side effect in src/polyfills.ts before any crypto runs.
 */
export const reactNativePlatform: PlatformCrypto = {
  async pbkdf2(password, salt, iterations, keyLenBytes) {
    return pbkdf2(sha256, password, salt, { c: iterations, dkLen: keyLenBytes })
  },

  randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length))
  },
}

// NOTE: this module must stay free of native-module imports. It is pure JS
// (@noble/hashes + the global CSPRNG), which is what lets the parity test import
// it under Node and prove the device KDF matches the web client's WebCrypto one.
// The full device platform (SQLite + keystore) is composed in reactNativeFull.ts.
