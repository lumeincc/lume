'use strict'

/**
 * Cross-checks the two lanes. When the same payload shows up both "reported by
 * the app" (fetch/WS hook) and "observed on the wire" (CDP), we can say the app
 * did not lie about what it transmitted. A match = a recent entry with the same
 * key but a DIFFERENT source, inside a short time window.
 *
 * Pure and testable: no browser, no timers — time is passed in via ev.timestamp.
 */

function hashStr(s) {
  let h = 5381
  const n = Math.min(s.length, 8192)
  for (let i = 0; i < n; i++) h = (((h << 5) + h) + s.charCodeAt(i)) | 0
  return h >>> 0
}

function makeCorrelator(opts) {
  opts = opts || {}
  const windowMs = opts.windowMs || 5000
  const max = opts.max || 300
  const recent = [] // { key, source, ts }

  function keyOf(ev) {
    const body = ev.body || ''
    return `${ev.kind}|${ev.method || ''}|${ev.path || ''}|${hashStr(body)}|${body.length}`
  }

  function prune(now) {
    while (recent.length && (now - recent[0].ts > windowMs || recent.length > max)) recent.shift()
  }

  /** Record an event and report whether the other lane already carried it. */
  function observe(ev, source) {
    const now = ev.timestamp || Date.now()
    prune(now)
    const key = keyOf(ev)
    const match = recent.find(r => r.key === key && r.source !== source)
    recent.push({ key, source, ts: now })
    return match ? { confirmed: true, matchedSource: match.source } : { confirmed: false, matchedSource: null }
  }

  return { observe, keyOf }
}

module.exports = { makeCorrelator, hashStr }
