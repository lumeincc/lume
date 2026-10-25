// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Validation for Web Push subscription endpoints (SEC-20260621-011).
 *
 * A stored push endpoint becomes an outbound request target for
 * `webpush.sendNotification()`. Without validation it is an SSRF primitive: a
 * client could subscribe with an internal URL and make the server fetch it.
 * We require HTTPS, bound the length, and reject loopback / private / link-local
 * literal hosts.
 *
 * Note: a public domain that *resolves* to a private IP is not caught here
 * (would require resolve-and-pin at send time — a deeper, separate mitigation).
 */

export const MAX_PUSH_ENDPOINT_LEN = 2048
export const MAX_PUSH_KEY_LEN = 512

function isBlockedHost(host: string): boolean {
  if (!host) return true
  if (host === 'localhost' || host.endsWith('.localhost')) return true

  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (v4) {
    const octets = v4.slice(1).map(Number)
    if (octets.some(n => n > 255)) return true
    const [a, b] = octets as [number, number, number, number]
    if (a === 0) return true // 0.0.0.0/8
    if (a === 127) return true // loopback
    if (a === 10) return true // private
    if (a === 192 && b === 168) return true // private
    if (a === 172 && b >= 16 && b <= 31) return true // private
    if (a === 169 && b === 254) return true // link-local (incl. 169.254.169.254 metadata)
    if (a === 100 && b >= 64 && b <= 127) return true // CGNAT 100.64.0.0/10
    return false
  }

  if (host.includes(':')) {
    const h = host.replace(/^\[|\]$/g, '')
    if (h === '::1' || h === '::') return true
    if (h.startsWith('fe80') || h.startsWith('fc') || h.startsWith('fd')) return true // link-local + unique-local
    // IPv4-mapped IPv6. Node normalizes `::ffff:127.0.0.1` to `::ffff:7f00:1`,
    // so handle both the dotted and the hex-group forms.
    if (h.startsWith('::ffff:')) {
      const rest = h.slice('::ffff:'.length)
      if (rest.includes('.')) return isBlockedHost(rest)
      const groups = rest.split(':')
      if (groups.length === 2) {
        const hi = parseInt(groups[0]!, 16)
        const lo = parseInt(groups[1]!, 16)
        if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
          const octets = [(hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff, lo & 0xff]
          return isBlockedHost(octets.join('.'))
        }
      }
    }
    return false
  }

  return false // a regular domain name
}

export function isSafePushEndpoint(endpoint: string): boolean {
  if (
    typeof endpoint !== 'string' ||
    endpoint.length === 0 ||
    endpoint.length > MAX_PUSH_ENDPOINT_LEN
  ) {
    return false
  }
  let url: URL
  try {
    url = new URL(endpoint)
  } catch {
    return false
  }
  if (url.protocol !== 'https:') return false
  return !isBlockedHost(url.hostname.toLowerCase())
}
