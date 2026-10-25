// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Where the client talks to the relay.
 *
 * Expo only inlines `EXPO_PUBLIC_*` variables at build time, so the web client's
 * `NEXT_PUBLIC_*` names resolve to undefined here — which would have silently
 * sent the app to localhost on a phone. Set them in a local `.env` to point at a
 * dev server; the defaults below are the deployed relay.
 *
 * These are not secrets: the server URL is public by definition, and the relay is
 * blind — every payload it receives is already sealed on this device.
 */

export const API_URL = process.env.EXPO_PUBLIC_API_URL ?? 'https://lume-api-3dnb.onrender.com/api'

export const WS_URL = process.env.EXPO_PUBLIC_WS_URL ?? 'wss://lume-api-3dnb.onrender.com/ws'

/**
 * The origin this client declares to the relay.
 *
 * In production the relay refuses state-changing requests that carry no `Origin`
 * header — CSRF protection written for browser clients, which send it
 * automatically. React Native's fetch sends none, so a native build is rejected
 * with 403 "Origin required" unless it states one explicitly.
 *
 * This value must be present in the relay's `CLIENT_ORIGIN` allowlist, so the
 * server keeps rejecting everything it has not been told about — the app becomes
 * an explicitly allowed origin rather than an exception to the rule. It is a
 * https:// URL rather than a custom scheme because the relay's allowlist resolves
 * entries through `new URL().origin`, which yields "null" for non-special schemes.
 */
export const APP_ORIGIN = process.env.EXPO_PUBLIC_APP_ORIGIN ?? 'https://app.lume.mobile'
