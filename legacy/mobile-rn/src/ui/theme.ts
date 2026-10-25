// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Design tokens, transcribed from the web client's globals.css.
 *
 * Values are copied, not reinterpreted: the mobile app must look like the web
 * LUME, and "close enough" is how one product turns into two. Where the web uses
 * a CSS class (`.auth-pill`, `.message-bubble-sent`, `.apple-input`) the exact
 * numbers are carried over in `metrics` below rather than re-invented per screen.
 *
 * The palette is monochrome on purpose. `hl` is the single accent and is used
 * only for presence.
 */

export interface Palette {
  background: string
  surface: string
  /** Cards, inputs and received bubbles sit on this, not on `surface`. */
  surfaceStrong: string
  surfaceAlt: string
  border: string
  textPrimary: string
  textSecondary: string
  textMuted: string
  accent: string
  accentContrast: string
  accentDisabled: string
  hl: string
  danger: string
  /** Received bubble: the web overrides surfaceStrong in dark mode. */
  bubbleIn: string
}

export const light: Palette = {
  background: '#f5f5f5',
  surface: 'rgba(255, 255, 255, 0.92)',
  surfaceStrong: '#ffffff',
  surfaceAlt: 'rgba(11, 11, 11, 0.04)',
  border: 'rgba(11, 11, 11, 0.12)',
  textPrimary: '#0b0b0b',
  textSecondary: 'rgba(11, 11, 11, 0.72)',
  textMuted: 'rgba(11, 11, 11, 0.48)',
  accent: '#0b0b0b',
  accentContrast: '#ffffff',
  accentDisabled: 'rgba(11, 11, 11, 0.25)',
  hl: '#16a34a',
  danger: '#dc2626',
  bubbleIn: '#ffffff',
}

export const dark: Palette = {
  background: '#050505',
  surface: 'rgba(15, 15, 15, 0.88)',
  surfaceStrong: '#0f0f0f',
  surfaceAlt: 'rgba(247, 247, 247, 0.06)',
  border: 'rgba(247, 247, 247, 0.14)',
  textPrimary: '#f7f7f7',
  textSecondary: 'rgba(247, 247, 247, 0.78)',
  textMuted: 'rgba(247, 247, 247, 0.52)',
  accent: '#f7f7f7',
  accentContrast: '#050505',
  accentDisabled: 'rgba(247, 247, 247, 0.25)',
  hl: '#4ade80',
  danger: '#f87171',
  // .message-bubble-received is overridden to this in dark mode.
  bubbleIn: '#262626',
}

/**
 * Typeface.
 *
 * The web serves Space Grotesk to the English UI and **Manrope** to the Russian
 * one — Space Grotesk carries no Cyrillic, so `globals.css` swaps `--font-sans`
 * wholesale on `html[lang="ru"]`. This app is Russian, so Manrope is the face,
 * and it is the same one the Russian deck uses.
 *
 * Until this existed the app rendered in Android's Roboto while every metric
 * here was transcribed correctly from the web — which is why the screens could
 * be numerically right and still look like a different product. Typeface is the
 * first thing the eye reads.
 *
 * React Native does not synthesise weights from one family: asking for
 * `fontWeight: '600'` on the regular face gives a faked bold that looks wrong.
 * Each weight is therefore its own family name, resolved by `fontFor` below —
 * never set `fontWeight` on its own.
 */
export const fonts = {
  regular: 'Manrope_400Regular',
  medium: 'Manrope_500Medium',
  semibold: 'Manrope_600SemiBold',
  bold: 'Manrope_700Bold',
} as const

export type FontWeight = '400' | '500' | '600' | '700'

export function fontFor(weight: FontWeight = '400'): string {
  switch (weight) {
    case '700':
      return fonts.bold
    case '600':
      return fonts.semibold
    case '500':
      return fonts.medium
    default:
      return fonts.regular
  }
}

export const radius = { md: 16, lg: 22, pill: 999 } as const

/** Font sizes named as the web names them. */
export const text = { micro: 10, caption: 11, body: 13, base: 16 } as const

export const space = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24 } as const

/** Exact numbers behind the web's component classes. */
export const metrics = {
  /** .auth-hero — max-width 320, margin auto, inside a vertically centred shell */
  authMaxWidth: 320,
  /**
   * .auth-title — `clamp(26px, 7vw, 30px)` resolves to 26.25px at 375pt wide,
   * with `line-height: 1.1` and `letter-spacing: -0.02em`. Centred.
   */
  authTitleSize: 26,
  authTitleLineHeight: 29,
  authTitleSpacing: -0.52,
  /** .auth-hint */
  authHintSize: 13.5,
  /** .auth-pill / .auth-pill-secondary */
  pillHeight: 50,
  pillPaddingV: 15,
  pillPaddingH: 20,
  pillFontSize: 15,
  /** .apple-input */
  inputPaddingV: 14,
  inputPaddingH: 16,
  inputFontSize: 16,
  /** .auth-field-label */
  labelSize: 13,
  /** ChatRow: px-4 py-3.5, min-h-[56px] */
  rowPaddingV: 14,
  rowPaddingH: 16,
  rowMinHeight: 56,
  /** .message-bubble-*: px-4 py-2.5 with asymmetric corners */
  bubblePaddingV: 10,
  bubblePaddingH: 16,
  bubbleRadius: 18,
  bubbleTail: 4,
} as const
