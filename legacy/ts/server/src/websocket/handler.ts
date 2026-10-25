// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { WebSocket, WebSocketServer } from 'ws'
import { IncomingMessage } from 'http'
import jwt from 'jsonwebtoken'

import database from '../db/database'
import { buildOriginAllowlist, isOriginAllowed } from '../utils/originAllowlist'
import { isValidMessageIds, isValidRecipientId } from '../utils/validators'
import { WsMessageSchema } from '../schemas/websocket'
import { getTrustedProxyHops } from '../utils/trustProxy'
import type { TypingMessage, ReadReceiptMessage } from '../schemas/websocket'

// Connected users map: userId -> Set<WebSocket>
const connectedUsers = new Map<string, Set<WebSocket>>()

/**
 * Sockets currently held open, per address.
 *
 * The handshake limiter bounds how *fast* one address may open connections (10
 * a minute); nothing bounded how many it could accumulate. Sustained, that is
 * 600 held sockets an hour from one caller, and the per-user cap of 5 does not
 * help because registering more accounts raises it.
 *
 * The default is deliberately generous, and that is a judgement rather than an
 * oversight. LUME's users are disproportionately behind shared exits — carrier
 * NAT, VPNs, Tor — where one address legitimately carries many people. A tight
 * per-IP cap on a privacy tool does not read as security to the person it locks
 * out; it reads as the product being broken on their network. So the per-IP
 * number is high enough to cover a shared exit, and the ceiling that actually
 * protects the process is the global one below.
 */
const connectionsByIp = new Map<string, Set<WebSocket>>()

/** Per-address concurrent sockets. High on purpose — see above. */
const MAX_CONNECTIONS_PER_IP = Number(process.env.WS_MAX_CONNECTIONS_PER_IP || 128)

/**
 * Total concurrent sockets for this process. This is the real protection: it
 * bounds memory and event-loop pressure no matter how the load is distributed
 * across addresses, which a per-IP rule cannot do once an attacker has more
 * than one address.
 */
const MAX_CONNECTIONS_TOTAL = Number(process.env.WS_MAX_CONNECTIONS_TOTAL || 5000)

/** Sockets currently held, across every address. */
function totalOpenConnections(): number {
  let total = 0
  for (const sockets of connectionsByIp.values()) total += sockets.size
  return total
}

function trackIpConnection(ip: string, ws: WebSocket): void {
  const existing = connectionsByIp.get(ip)
  if (existing) {
    existing.add(ws)
    return
  }
  connectionsByIp.set(ip, new Set([ws]))
}

function releaseIpConnection(ip: string, ws: WebSocket): void {
  const sockets = connectionsByIp.get(ip)
  if (!sockets) return
  sockets.delete(ws)
  // Delete the empty set rather than leaving it: the map is keyed by a
  // caller-influenced value, so an entry that is never removed is a slow leak
  // an attacker can drive by rotating addresses.
  if (sockets.size === 0) connectionsByIp.delete(ip)
}

// Rate limits
const connectionRateLimits = new Map<string, number[]>() // IP -> timestamps
const typingRateLimits = new Map<string, { lastAt: number; state: boolean }>()
const ORIGIN_ALLOWLIST = buildOriginAllowlist(process.env.CLIENT_ORIGIN || 'http://localhost:3000')

let rateLimitCleanupInterval: NodeJS.Timeout | null = null

export interface AuthenticatedWebSocket extends WebSocket {
  userId: string
  username: string
  isAlive: boolean // Heartbeat flag
  /** Address this socket was bucketed under, so `close` releases the same slot. */
  clientIp?: string
  /** Inbound frame budget, per socket. See `withinFrameBudget`. */
  frameWindowStart?: number
  frameCount?: number
  readCount?: number
}

/**
 * Per-connection inbound frame budget. SEC-20260721-005.
 *
 * `typing` was throttled; `ping` and `read` were not. `ping` costs a parse, a
 * Zod check, a serialise and a send per frame, and `read` fans out to every
 * socket of a chosen recipient — a targeted denial of service delivered through
 * our own relay. The 5-sockets-per-user cap bounds connections, not frame rate.
 *
 * The counters live on the socket rather than in a Map keyed by user or IP: they
 * are freed when the connection closes, so there is nothing to prune and no
 * unbounded map to grow — the failure mode the neighbouring
 * `connectionRateLimits` has.
 *
 * Budgets are deliberately loose. A real client sends a heartbeat every ~25s
 * plus typing and read bursts when a chat is opened; these bound a flood without
 * being reachable by ordinary use.
 */
const FRAME_WINDOW_MS = 10_000
const MAX_FRAMES_PER_WINDOW = 120
const MAX_READ_FRAMES_PER_WINDOW = 20
/** Well past a bursty-but-honest client; treated as deliberate. */
const FRAME_FLOOD_CLOSE_THRESHOLD = MAX_FRAMES_PER_WINDOW * 3

type FrameBudget = 'ok' | 'over' | 'flooding'

function withinFrameBudget(ws: AuthenticatedWebSocket, type: string): FrameBudget {
  const now = Date.now()

  if (ws.frameWindowStart === undefined || now - ws.frameWindowStart >= FRAME_WINDOW_MS) {
    ws.frameWindowStart = now
    ws.frameCount = 0
    ws.readCount = 0
  }

  ws.frameCount = (ws.frameCount ?? 0) + 1
  if (type === 'read') ws.readCount = (ws.readCount ?? 0) + 1

  if (ws.frameCount > FRAME_FLOOD_CLOSE_THRESHOLD) return 'flooding'
  if (ws.frameCount > MAX_FRAMES_PER_WINDOW) return 'over'
  if (type === 'read' && (ws.readCount ?? 0) > MAX_READ_FRAMES_PER_WINDOW) return 'over'
  return 'ok'
}

/**
 * Trusted proxy hops, read from the same function `index.ts` configures Express
 * with. Both sides must agree — the HTTP limiter and the WebSocket handshake
 * limiter have to bucket one caller into one key — and this used to be a
 * duplicated constant kept in step by a comment. Deployments change the chain
 * (Cloudflare in front of Render adds a hop), and a number that must be edited
 * in two files is one that will eventually be edited in one.
 */

/**
 * Resolves the client address for rate-limit bucketing. SEC-20260721-004.
 *
 * `X-Forwarded-For` reads left to right as oldest to newest: the leftmost entry
 * is whatever the *client* sent, and each proxy appends the address it received
 * the connection from. So the entry a trusted proxy added is on the **right**,
 * and the leftmost is attacker-controlled.
 *
 * This previously returned `ips[0]` — the client's own claim. A handshake with
 * `X-Forwarded-For: <random>` therefore landed in a fresh bucket every time and
 * the 10/minute limiter never fired, while still appearing to be enforced.
 *
 * Walking in from the right by the trusted depth is what Express's
 * `trust proxy` does, which is why the HTTP path never had this bug.
 */
function getClientIp(req: IncomingMessage): string {
  const trustedHopCount = getTrustedProxyHops()

  const socketAddress = req.socket.remoteAddress || 'unknown'
  if (trustedHopCount === 0) return socketAddress

  const xForwardedFor = req.headers['x-forwarded-for']
  if (!xForwardedFor) return socketAddress

  // Node collapses repeated headers into an array; join so a client cannot hide
  // entries by splitting them across duplicate header lines.
  const raw = Array.isArray(xForwardedFor) ? xForwardedFor.join(',') : xForwardedFor
  const entries = raw
    .split(',')
    .map(entry => entry.trim())
    .filter(entry => entry.length > 0)

  // Fewer entries than trusted hops means the header did not come through the
  // expected chain. Fall back to the socket peer, which cannot be forged.
  if (entries.length < trustedHopCount) return socketAddress

  // Take the trusted tail and read its head. A computed index here would be a
  // request-derived member access, which `security/detect-object-injection`
  // rejects; `.at()` is unavailable under the server's current `lib` target and
  // raising that for one call is not worth the blast radius.
  const trustedHops = entries.slice(-trustedHopCount)
  return trustedHops[0] ?? socketAddress
}

export function initWebSocket(wss: WebSocketServer): void {
  if (!rateLimitCleanupInterval) {
    rateLimitCleanupInterval = setInterval(() => {
      const now = Date.now()
      for (const [ip, timestamps] of connectionRateLimits.entries()) {
        const validTimestamps = timestamps.filter(t => now - t < 60_000)
        if (validTimestamps.length === 0) {
          connectionRateLimits.delete(ip)
        } else {
          connectionRateLimits.set(ip, validTimestamps)
        }
      }

      for (const [key, value] of typingRateLimits.entries()) {
        if (now - value.lastAt > 10 * 60 * 1000) {
          typingRateLimits.delete(key)
        }
      }
    }, 60_000)
  }

  wss.on('connection', (ws: AuthenticatedWebSocket, req: IncomingMessage) => {
    ws.isAlive = true

    /**
     * Close with a code the client can actually read.
     *
     * `close()` only queues the frame; `terminate()` destroys the socket at
     * once, so calling them back to back loses the code and the client sees a
     * bare 1006 — indistinguishable from the network dying. The delay lets the
     * frame flush. SEC-20260805-004.
     */
    const abort = (code: number, reason: string) => {
      ws.close(code, reason)
      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CLOSING) {
          ws.terminate()
        }
      }, 1000)
    }

    if (process.env.NODE_ENV === 'development' && process.env.WS_DEV_FORCE_CLOSE_CODE) {
      const forceCode = parseInt(process.env.WS_DEV_FORCE_CLOSE_CODE, 10)
      if (!Number.isNaN(forceCode)) {
        console.warn(`[DEV] Forcing connection close with code: ${forceCode}`)
        ws.close(forceCode, 'DEV_FORCE_CLOSE')
        ws.terminate()
        return
      }
    }

    // Handshake rate limit by IP (10 per minute)
    const ip = getClientIp(req)
    const now = Date.now()
    const timestamps = connectionRateLimits.get(ip) || []
    const validTimestamps = timestamps.filter(t => now - t < 60_000)

    if (validTimestamps.length >= 10) {
      return abort(4006, 'Rate limit exceeded')
    }

    validTimestamps.push(now)
    connectionRateLimits.set(ip, validTimestamps)

    // Checked before any authentication work: refusing here costs a comparison,
    // whereas refusing after the JWT verification would have the attacker
    // setting the price.
    if (totalOpenConnections() >= MAX_CONNECTIONS_TOTAL) {
      return abort(4005, 'Server connection limit reached')
    }
    const openFromThisIp = connectionsByIp.get(ip)?.size ?? 0
    if (openFromThisIp >= MAX_CONNECTIONS_PER_IP) {
      return abort(4005, 'Too many connections from this address')
    }

    ws.clientIp = ip
    trackIpConnection(ip, ws)

    const skipOriginCheck =
      process.env.SKIP_ORIGIN_CHECK === '1' &&
      (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'test')
    if (!skipOriginCheck) {
      const origin = (req.headers.origin as string | undefined) || ''
      if (!isOriginAllowed(origin, ORIGIN_ALLOWLIST)) {
        return abort(4007, 'Origin not allowed')
      }
    }

    // Sec-WebSocket-Protocol: expect "lume" plus "auth.<token>"
    const protocols = req.headers['sec-websocket-protocol']

    let token: string | undefined
    let hasLumeProtocol = false

    if (protocols) {
      const parts = protocols.split(',').map(p => p.trim())
      for (const part of parts) {
        if (part === 'lume') {
          hasLumeProtocol = true
        } else if (part.startsWith('auth.')) {
          token = part.slice(5)
        }
      }
    }

    if (!hasLumeProtocol) {
      return abort(4002, 'Missing protocol marker')
    }

    if (!token) {
      return abort(4001, 'Missing auth token')
    }

    try {
      const decoded = jwt.verify(token, process.env.WS_JWT_SECRET as string, {
        audience: 'lume-ws',
        issuer: 'lume',
        algorithms: ['HS256'],
      }) as jwt.JwtPayload

      if (!decoded.sub || typeof decoded.sub !== 'string') {
        throw new Error('No subject in token')
      }

      const userId = decoded.sub
      ws.userId = userId

      const user = database.getUserById(userId)
      if (!user) {
        return abort(4002, 'User not found')
      }

      ws.username = user.username
      addConnection(userId, ws)
      database.touchLastSeen(userId)
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return abort(4003, 'Token expired')
      }
      return abort(4002, 'Invalid token')
    }

    ws.on('pong', () => {
      ws.isAlive = true
    })

    ws.on('message', (data: Buffer) => {
      try {
        if (ws.readyState !== WebSocket.OPEN) return

        // Reject oversized payloads (64 KB max for any WS message)
        if (data.length > 65_536) return

        const raw = data.toString()
        const parsed = JSON.parse(raw)
        const result = WsMessageSchema.safeParse(parsed)
        if (!result.success) return
        const message = result.data

        // Budget checked after parsing so the type is known — `read` gets a
        // tighter allowance than the rest. SEC-20260721-005.
        const budget = withinFrameBudget(ws, message.type)
        if (budget === 'flooding') {
          // Well past any plausible client. Dropping frames silently would let
          // it keep burning a parse per frame indefinitely, so the connection
          // goes instead. 1008 is the policy-violation close code.
          ws.close(1008, 'Message rate exceeded')
          return
        }
        if (budget === 'over') return

        switch (message.type) {
          case 'ping':
            ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }))
            break

          case 'typing': {
            if (!isValidRecipientId(message.recipientId)) break
            // Prevent sending typing to self
            if (message.recipientId === ws.userId) break
            if (database.isBlocked(message.recipientId, ws.userId)) break
            if (
              message.groupId &&
              !bothGroupMembers(message.groupId, ws.userId, message.recipientId)
            )
              break
            handleTyping(ws.userId, ws.username, message)
            break
          }

          case 'read': {
            if (!isValidRecipientId(message.recipientId)) break
            if (!isValidMessageIds(message.messageIds)) break
            // Prevent sending read receipt to self
            if (message.recipientId === ws.userId) break
            if (database.isBlocked(message.recipientId, ws.userId)) break
            if (
              message.groupId &&
              !bothGroupMembers(message.groupId, ws.userId, message.recipientId)
            )
              break
            handleReadReceipt(ws.userId, message)
            break
          }

          default:
            break
        }
      } catch (error) {
        console.error('WS parse error:', error instanceof Error ? error.message : String(error))
      }
    })

    ws.on('close', () => {
      // Released unconditionally: a socket that never finished authenticating
      // still occupied a slot, and leaking those is precisely the accumulation
      // this cap exists to stop.
      if (ws.clientIp) releaseIpConnection(ws.clientIp, ws)
      if (ws.userId) {
        removeConnection(ws.userId, ws)
        database.touchLastSeen(ws.userId)
      }
    })

    ws.on('error', error => {
      console.error('WS error:', error instanceof Error ? error.message : String(error))
    })
  })

  // Heartbeat
  const interval = setInterval(() => {
    wss.clients.forEach(ws => {
      const extWs = ws as AuthenticatedWebSocket
      if (extWs.isAlive === false) {
        return ws.terminate()
      }
      extWs.isAlive = false
      ws.ping()
    })
  }, 30_000)

  wss.on('close', () => {
    clearInterval(interval)
    if (rateLimitCleanupInterval) {
      clearInterval(rateLimitCleanupInterval)
      rateLimitCleanupInterval = null
    }
  })
}

// When a typing/read event is scoped to a group, only relay it if BOTH the
// sender and the recipient are members of that group. Otherwise a non-member
// could probe or spam group participants. SEC-20260621-013.
function bothGroupMembers(groupId: string, a: string, b: string): boolean {
  const memberIds = new Set(database.getGroupMembers(groupId).map(m => m.user_id))
  return memberIds.has(a) && memberIds.has(b)
}

function handleTyping(senderId: string, senderUsername: string, message: TypingMessage): void {
  const now = Date.now()
  // Scope the rate-limit key by group so a group fan-out and a 1:1 typing event
  // to the same recipient do not suppress each other.
  const key = `${senderId}|${message.recipientId}|${message.groupId ?? ''}`
  const prev = typingRateLimits.get(key)
  if (prev) {
    if (prev.state === message.isTyping && now - prev.lastAt < 800) {
      return
    }
    if (now - prev.lastAt < 150) {
      return
    }
  }
  typingRateLimits.set(key, { lastAt: now, state: message.isTyping })

  broadcastToUser(message.recipientId, {
    type: 'typing',
    senderId,
    senderUsername,
    isTyping: message.isTyping,
    ...(message.groupId ? { groupId: message.groupId } : {}),
  })
}

function handleReadReceipt(senderId: string, message: ReadReceiptMessage): void {
  // Validate: max 100 IDs per receipt, all strings
  const ids = message.messageIds
  if (ids.length === 0 || ids.length > 100 || ids.some(id => typeof id !== 'string')) {
    return
  }

  broadcastToUser(message.recipientId, {
    type: 'read',
    senderId,
    messageIds: ids,
    ...(message.groupId ? { groupId: message.groupId } : {}),
  })
}

function addConnection(userId: string, ws: WebSocket): void {
  if (!connectedUsers.has(userId)) {
    connectedUsers.set(userId, new Set())
  }

  const connections = connectedUsers.get(userId)!

  if (connections.size >= 5) {
    const oldest = connections.values().next().value
    if (oldest) {
      try {
        oldest.close(4005, 'Too many connections')
        setTimeout(() => {
          if (oldest.readyState === WebSocket.OPEN || oldest.readyState === WebSocket.CLOSING) {
            try {
              oldest.terminate()
            } catch {
              /* ignore */
            }
          }
        }, 1000)
      } catch (e) {
        console.error('Error closing old socket:', e instanceof Error ? e.message : String(e))
      }
      connections.delete(oldest)
    }
  }

  connections.add(ws)
}

function removeConnection(userId: string, ws: WebSocket): void {
  const connections = connectedUsers.get(userId)
  if (connections) {
    connections.delete(ws)
    if (connections.size === 0) {
      connectedUsers.delete(userId)
    }
  }
}

export function broadcastToUser(userId: string, message: object): boolean {
  const connections = connectedUsers.get(userId)
  if (!connections || connections.size === 0) {
    return false
  }

  const payload = JSON.stringify(message)
  let delivered = false

  for (const ws of connections) {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(payload)
        delivered = true
      } catch {
        connections.delete(ws)
      }
    } else if (ws.readyState === WebSocket.CLOSED) {
      connections.delete(ws)
    }
  }

  if (connections.size === 0) {
    connectedUsers.delete(userId)
  }

  return delivered
}

export function isUserOnline(userId: string): boolean {
  const connections = connectedUsers.get(userId)
  return connections !== undefined && connections.size > 0
}

export function getConnectionStats(): { users: number; connections: number } {
  let totalConnections = 0
  for (const connections of connectedUsers.values()) {
    totalConnections += connections.size
  }

  return {
    users: connectedUsers.size,
    connections: totalConnections,
  }
}
