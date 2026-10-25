// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { requireOptionalNativeModule } from 'expo'

interface LumeCryptoNativeModule {
  pbkdf2Base64(passwordB64: string, saltB64: string, iterations: number, keyLenBytes: number): Promise<string>
}

/**
 * Optional on purpose: `requireOptionalNativeModule` returns null instead of
 * throwing when the module is absent (Expo Go, a stale build, iOS for now), so
 * the platform adapter can fall back to the pure-JS implementation rather than
 * crashing at import time — the failure mode that already cost us one broken APK.
 */
export const LumeCrypto = requireOptionalNativeModule<LumeCryptoNativeModule>('LumeCrypto')

export const hasNativePbkdf2 = LumeCrypto != null
