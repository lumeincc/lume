// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Haptic feedback utilities for PWA (iOS/Android).
 * Uses navigator.vibrate when available, no-op otherwise.
 */

export const tapFeedback = (): void => {
  navigator.vibrate?.(8)
}

export const errorFeedback = (): void => {
  navigator.vibrate?.([10, 50, 10])
}

export const successFeedback = (): void => {
  navigator.vibrate?.(15)
}
