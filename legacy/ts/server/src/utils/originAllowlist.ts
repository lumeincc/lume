// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

function normalizeRaw(value: string): string {
  return value.trim().replace(/\/+$/, '')
}

function toOrigin(value: string): string | null {
  const trimmed = normalizeRaw(value)
  if (!trimmed) return null
  try {
    const url = new URL(trimmed)
    return url.origin.toLowerCase()
  } catch {
    return null
  }
}

function toHost(value: string): string | null {
  const trimmed = normalizeRaw(value)
  if (!trimmed) return null

  const hasScheme =
    trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.startsWith('//')
  const withScheme = hasScheme ? trimmed : `https://${trimmed}`
  try {
    const url = new URL(withScheme)
    return url.host.toLowerCase()
  } catch {
    return null
  }
}

export interface OriginAllowlist {
  raw: string[]
  allowedOrigins: Set<string>
  allowedHosts: Set<string>
}

export function buildOriginAllowlist(source: string): OriginAllowlist {
  const raw = source
    .split(',')
    .map(s => normalizeRaw(s))
    .filter(Boolean)

  const allowedOrigins = new Set<string>()
  const allowedHosts = new Set<string>()

  for (const item of raw) {
    const hasScheme =
      item.startsWith('http://') || item.startsWith('https://') || item.startsWith('//')
    if (hasScheme) {
      // Schemeful entry: pin to the exact origin so https cannot be downgraded to http.
      const normalizedOrigin = toOrigin(item)
      if (normalizedOrigin) {
        allowedOrigins.add(normalizedOrigin)
      }
    } else {
      // Bare host config: match the host under any scheme (explicit opt-in).
      const host = toHost(item)
      if (host) {
        allowedHosts.add(host)
      }
    }
  }

  return { raw, allowedOrigins, allowedHosts }
}

export function isOriginAllowed(origin: string | undefined, allowlist: OriginAllowlist): boolean {
  if (!origin) return false

  const normalizedOrigin = toOrigin(origin)
  if (!normalizedOrigin) return false

  if (allowlist.allowedOrigins.has(normalizedOrigin)) {
    return true
  }

  const host = toHost(normalizedOrigin)
  if (!host) return false
  return allowlist.allowedHosts.has(host)
}
