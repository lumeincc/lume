// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Must be imported before any crypto runs (first line of the root layout, and
 * again at the top of any screen that touches crypto — the import is idempotent
 * and route-module evaluation order is not guaranteed).
 *
 * Registers a native CSPRNG as global `crypto.getRandomValues`, which TweetNaCl
 * and BIP39 depend on. Without it, key generation on device would throw.
 */
import 'react-native-get-random-values'

// Buffer + TextEncoder/TextDecoder, which React Native does not provide.
// Split into its own react-native-free module so it can be unit-tested.
import './polyfills.core'
