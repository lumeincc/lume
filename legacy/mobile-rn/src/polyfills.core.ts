// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Globals the crypto stack assumes but React Native does not provide.
 *
 * RN 0.76 polyfills only Blob, File, FileReader, FormData, Headers, Promise,
 * Request, Response, URL, URLSearchParams, WebSocket, XMLHttpRequest, fetch and
 * regeneratorRuntime — verified by reading its polyfillGlobal calls. Missing:
 *
 *   Buffer                 — bip39 builds mnemonics with Buffer.from/isBuffer,
 *                            and tweetnacl-util falls back to it for base64.
 *   TextEncoder/Decoder    — used by the ratchet, key vault, safety numbers,
 *                            master-key derivation, and @noble/hashes.
 *
 * Without these the app crashes the moment an identity is created. Kept free of
 * any react-native import so the whole thing is testable under Node — see
 * __tests__/hermes-env.test.ts, which strips these globals and proves the
 * polyfills restore a working crypto path.
 *
 * Every install is conditional: if a runtime already provides a global (Node, or
 * a future Hermes), the native one wins.
 */

import { Buffer as BufferPolyfill } from 'buffer'

type Mutable = Record<string, unknown>
const g = globalThis as unknown as Mutable

if (typeof g.Buffer === 'undefined') {
  g.Buffer = BufferPolyfill
}

if (typeof g.TextEncoder === 'undefined') {
  // UTF-8 encoding delegated to the Buffer polyfill rather than hand-rolled, so
  // multi-byte and surrogate-pair handling is the battle-tested implementation.
  g.TextEncoder = class TextEncoderPolyfill {
    readonly encoding = 'utf-8'
    encode(input = ''): Uint8Array {
      return new Uint8Array(BufferPolyfill.from(input, 'utf8'))
    }
  }
}

if (typeof g.TextDecoder === 'undefined') {
  g.TextDecoder = class TextDecoderPolyfill {
    readonly encoding = 'utf-8'
    decode(input?: Uint8Array | ArrayBuffer): string {
      if (input === undefined) return ''
      const bytes = input instanceof Uint8Array ? input : new Uint8Array(input)
      return BufferPolyfill.from(bytes).toString('utf8')
    }
  }
}

export {}
