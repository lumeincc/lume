'use strict'

/**
 * Turns raw Chrome DevTools Protocol (CDP) Network events into the normalized
 * shape the classifier understands. Kept separate and pure so the messy CDP
 * payload shapes stay out of the classification logic.
 */

function parseUrl(u) {
  try {
    const url = new URL(u)
    return { host: url.host, scheme: url.protocol.replace(':', ''), path: url.pathname }
  } catch {
    return null
  }
}

function byteLength(s) {
  return typeof s === 'string' ? Buffer.byteLength(s, 'utf8') : 0
}

/** Network.requestWillBeSent → normalized HTTP event (or null to ignore). */
function normalizeHttp(params) {
  const req = params && params.request
  if (!req || !req.url) return null
  const parsed = parseUrl(req.url)
  if (!parsed || !/^https?$/.test(parsed.scheme)) return null // skip data:, blob:, chrome-extension:
  return {
    kind: 'http',
    method: req.method || 'GET',
    url: req.url,
    host: parsed.host,
    scheme: parsed.scheme,
    path: parsed.path,
    resourceType: params.type || null,
    body: typeof req.postData === 'string' ? req.postData : null,
    size: byteLength(req.postData),
    timestamp: Date.now(),
  }
}

/**
 * Network.webSocketFrame{Sent,Received} → normalized WS event.
 * `host` is resolved by the caller from the requestId→url map, since the frame
 * event itself does not carry the URL.
 */
function normalizeWs(params, direction, host) {
  const frame = params && params.response ? params.response : {}
  const payload = typeof frame.payloadData === 'string' ? frame.payloadData : ''
  return {
    kind: 'ws',
    direction,
    host: host || null,
    scheme: 'wss',
    opcode: typeof frame.opcode === 'number' ? frame.opcode : undefined,
    body: payload || null,
    size: byteLength(payload),
    timestamp: Date.now(),
  }
}

/**
 * Payload reported by the in-page hook (see inject.js) → normalized event.
 * Mirrors the wire normalizers so both lanes classify through the same path.
 */
function normalizeApp(payload) {
  const p = payload || {}
  if (p.kind === 'telemetry') {
    return Object.assign({ kind: 'telemetry', timestamp: Date.now() }, p)
  }
  if (p.kind === 'ws') {
    const parsed = p.url ? parseUrl(p.url) : null
    return {
      kind: 'ws',
      direction: p.direction || 'out',
      host: parsed ? parsed.host : null,
      scheme: 'wss',
      body: typeof p.body === 'string' ? p.body : null,
      size: byteLength(p.body),
      timestamp: Date.now(),
    }
  }
  const parsed = p.url ? parseUrl(p.url) : null
  if (!parsed || !/^https?$/.test(parsed.scheme)) return null
  return {
    kind: 'http',
    method: p.method || 'GET',
    url: p.url,
    host: parsed.host,
    scheme: parsed.scheme,
    path: parsed.path,
    resourceType: 'Fetch',
    body: typeof p.body === 'string' ? p.body : null,
    size: byteLength(p.body),
    timestamp: Date.now(),
  }
}

module.exports = { normalizeHttp, normalizeWs, normalizeApp, parseUrl }
