// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import 'dotenv/config'
import express from 'express'
import compression from 'compression'
import cors from 'cors'
import helmet from 'helmet'
import crypto from 'crypto'
import { createServer } from 'http'
import { WebSocketServer } from 'ws'

import authRoutes from './routes/auth'
import messageRoutes from './routes/messages'
import fileRoutes, { deleteFileBlobs } from './routes/files'
import groupRoutes from './routes/groups'
import pushRoutes from './routes/push'
import profileRoutes from './routes/profile'
import { initWebSocket, getConnectionStats } from './websocket/handler'
import database from './db/database'
import { buildOriginAllowlist, isOriginAllowed } from './utils/originAllowlist'
import { validateWsJwtSecret } from './utils/validateSecret'
import { validateJsonLimit } from './utils/validateJsonLimit'
import { parseTrustProxyHops, getTrustedProxyHops } from './utils/trustProxy'
import { redactSensitivePath } from './utils/logRedaction'
import rateLimit from 'express-rate-limit'

const wsSecretCheck = validateWsJwtSecret(process.env.WS_JWT_SECRET)
if (!wsSecretCheck.ok) {
  console.error(`FATAL ERROR: ${wsSecretCheck.reason}.`)
  process.exit(1)
}

const app = express()
app.disable('x-powered-by')

// Refuse to boot on an unparseable value rather than falling back to 0. A
// silent fallback would put every caller in one rate-limit bucket, which looks
// like the limiter working right up until it denies service to everyone.
const trustProxyCheck = parseTrustProxyHops(process.env.TRUST_PROXY)
if (!trustProxyCheck.ok) {
  console.error(`FATAL ERROR: ${trustProxyCheck.reason}.`)
  process.exit(1)
}
const TRUSTED_PROXY_HOPS = getTrustedProxyHops()
if (TRUSTED_PROXY_HOPS > 0) {
  app.set('trust proxy', TRUSTED_PROXY_HOPS)
}

const PORT = Number(process.env.PORT) || 3001
const HOST = process.env.HOST || '0.0.0.0'
const jsonLimitCheck = validateJsonLimit(process.env.JSON_LIMIT)
if (!jsonLimitCheck.ok) {
  console.error(`FATAL ERROR: ${jsonLimitCheck.reason}.`)
  process.exit(1)
}
const JSON_LIMIT = jsonLimitCheck.value
const WS_MAX_PAYLOAD_BYTES = Number(process.env.WS_MAX_PAYLOAD_BYTES || 64 * 1024)
const IS_PROD = process.env.NODE_ENV === 'production'
const ORIGIN_ALLOWLIST = buildOriginAllowlist(process.env.CLIENT_ORIGIN || 'http://localhost:3000')
const CLIENT_ORIGINS = ORIGIN_ALLOWLIST.raw

const corsOptions = {
  origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    if (!origin) return callback(null, true)
    if (isOriginAllowed(origin, ORIGIN_ALLOWLIST)) {
      return callback(null, true)
    }
    return callback(new Error('Origin not allowed'))
  },
  credentials: true,
}

// === Middleware =============================================================

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    dnsPrefetchControl: { allow: false },
    strictTransportSecurity: {
      maxAge: 63072000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: 'no-referrer' },
  })
)

app.use(cors(corsOptions))
app.options(/.*/, cors(corsOptions))

// Require Origin in production for state-changing requests.
app.use((req, res, next) => {
  if (!IS_PROD) return next()
  const origin = req.headers.origin
  const method = req.method.toUpperCase()
  if (!origin && method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    res.status(403).json({ error: 'Origin required' })
    return
  }
  next()
})

// Explicit CORS error handler -> 403
app.use(
  (err: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (
      err &&
      typeof err === 'object' &&
      'message' in err &&
      (err as { message: string }).message === 'Origin not allowed'
    ) {
      res.status(403).json({ error: 'Origin not allowed' })
      return
    }
    next(err)
  }
)

app.use(compression())

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
  next()
})

app.use(
  express.json({
    limit: JSON_LIMIT,
    verify: (req, _res, buf) => {
      ;(req as express.Request & { rawBody?: string }).rawBody = buf.toString('utf8')
    },
  })
)

app.use(
  (err: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (err instanceof SyntaxError && 'message' in err) {
      res.status(400).json({ error: 'Invalid JSON body' })
      return
    }
    next(err)
  }
)

if (process.env.LOG_HTTP === '1') {
  app.use((req, res, next) => {
    const start = Date.now()
    res.on('finish', () => {
      const duration = Date.now() - start
      console.log(`${req.method} ${redactSensitivePath(req.path)} ${res.statusCode} ${duration}ms`)
    })
    next()
  })
}

// === Routes =================================================================

app.use('/api/auth', authRoutes)
app.use('/api/messages', messageRoutes)
app.use('/api/files', fileRoutes)
app.use('/api/groups', groupRoutes)
app.use('/api/push', pushRoutes)
app.use('/api/profile', profileRoutes)

const publicRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: express.Request): string => `public:ip:${req.ip || '127.0.0.1'}`,
})

app.get('/api/health', publicRateLimit, (_req, res) => {
  try {
    database.ping()
    res.json({ status: 'ok', timestamp: new Date().toISOString() })
  } catch {
    res.status(503).json({ status: 'degraded', timestamp: new Date().toISOString() })
  }
})

app.get('/api/metrics', publicRateLimit, (req, res) => {
  const token = req.headers['x-metrics-token']
  if (IS_PROD) {
    const providedToken =
      typeof token === 'string' ? token : Array.isArray(token) ? token[0] || '' : ''
    const expectedToken = String(process.env.METRICS_SECRET || '')
    if (!expectedToken) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }
    const providedHash = crypto.createHash('sha256').update(providedToken).digest()
    const expectedHash = crypto.createHash('sha256').update(expectedToken).digest()
    if (!crypto.timingSafeEqual(providedHash, expectedHash)) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }
  }

  const stats = getConnectionStats()
  const mem = process.memoryUsage()
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptimeSec: Math.floor(process.uptime()),
    ws: stats,
    memory: {
      rss: mem.rss,
      heapTotal: mem.heapTotal,
      heapUsed: mem.heapUsed,
      external: mem.external,
    },
  })
})

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' })
})

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err.message !== 'Origin not allowed') {
    console.error('Unhandled error:', err instanceof Error ? err.message : String(err))
  }
  res.status(500).json({ error: 'Unexpected server error' })
})

// === Server Startup =========================================================

const server = createServer(app)

const wss = new WebSocketServer({
  server,
  path: '/ws',
  perMessageDeflate: false,
  maxPayload: Number.isFinite(WS_MAX_PAYLOAD_BYTES) ? WS_MAX_PAYLOAD_BYTES : 64 * 1024,
})
initWebSocket(wss)

/**
 * Socket timeouts. Node's defaults are generous — 60s for headers, 300s for a
 * whole request — which leaves a cheap way to tie up connections: open many,
 * send a byte of the request line every so often, never finish.
 *
 * The two are set apart on purpose, because they defend different things and
 * one of them can break the product if it is tightened naively.
 *
 * `headersTimeout` is the slow-loris control and is independent of how big the
 * body is: headers are small, so a caller that cannot finish them in 20 seconds
 * is not on a bad connection, it is holding the socket open deliberately.
 *
 * `requestTimeout` covers the body, and the body here can legitimately be large.
 * An attachment is 5 MB, base64-encoded into JSON, so roughly 6.7 MB on the
 * wire — which is where the 8 MB JSON_LIMIT comes from. On a poor mobile uplink
 * (~500 kbps) that upload takes close to two minutes. A 30-second request
 * timeout would look like sensible hardening and would silently break sending a
 * photo on a train. 120 seconds is well under Node's 300 and still above a
 * realistic worst-case upload.
 *
 * `keepAliveTimeout` is deliberately left at Node's default. Lowering it behind
 * a proxy is the classic cause of sporadic 502s: the proxy reuses a connection
 * in the same instant the origin closes it. It is only worth touching against a
 * known load-balancer idle timeout, and Render's is not documented here.
 */
const HEADERS_TIMEOUT_MS = Number(process.env.HEADERS_TIMEOUT_MS || 20_000)
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 120_000)

// Node requires headersTimeout to exceed keepAliveTimeout, or it warns and the
// header deadline is effectively ignored.
if (HEADERS_TIMEOUT_MS <= server.keepAliveTimeout) {
  console.error(
    `FATAL ERROR: HEADERS_TIMEOUT_MS (${HEADERS_TIMEOUT_MS}) must exceed keepAliveTimeout (${server.keepAliveTimeout}).`
  )
  process.exit(1)
}

server.headersTimeout = HEADERS_TIMEOUT_MS
server.requestTimeout = REQUEST_TIMEOUT_MS

server.listen(PORT, HOST, () => {
  // Startup diagnostics — helps debug "account not found" issues
  const dbStats = database.getStartupDiagnostics()
  console.log(
    `LUME API listening on http://${HOST}:${PORT} (ws path /ws) | Allowed origins: ${CLIENT_ORIGINS.join(', ') || 'none'}`
  )
  console.log(
    `DB: ${dbStats.path} | Users: ${dbStats.userCount} | Size: ${(dbStats.sizeBytes / 1024 / 1024).toFixed(1)}MB`
  )
})

// Periodic cleanup: purge pending messages older than 30 days
const STALE_MSG_MAX_AGE_SEC = 30 * 24 * 60 * 60 // 30 days
const STALE_MSG_CLEANUP_INTERVAL = 60 * 60 * 1000 // every hour

const staleCleanupTimer = setInterval(() => {
  const purged = database.purgeStaleMessages(STALE_MSG_MAX_AGE_SEC)
  if (purged > 0) {
    console.log(`Purged ${purged} stale pending message(s)`)
  }
}, STALE_MSG_CLEANUP_INTERVAL)
staleCleanupTimer.unref()

// Purge expired files every minute (DB rows + on-disk blobs)
const fileCleanupTimer = setInterval(() => {
  const purgedIds = database.purgeExpiredFiles(Math.floor(Date.now() / 1000))
  if (purgedIds.length > 0) {
    void deleteFileBlobs(purgedIds)
    console.log(`Purged ${purgedIds.length} expired file(s)`)
  }
}, 60_000)
fileCleanupTimer.unref()

// Cleanup old request signatures every 5 minutes
const sigCleanupTimer = setInterval(
  () => {
    const cutoff = Math.floor(Date.now() / 1000) - 180
    database.cleanupRequestSignatures(cutoff)
  },
  5 * 60 * 1000
)
sigCleanupTimer.unref()

/**
 * Reclaim accounts nobody has used, releasing their usernames.
 *
 * The `users` table was the only one with no bound: an account is a row plus
 * twenty prekeys, nothing pruned them, and the rate limiter alone let one
 * address accumulate hundreds a day. Deleting the row is safe by design — it is
 * a cache, and a client re-binds its existing identity silently on next unlock
 * — but the username it releases can then be claimed by someone else, which is
 * the part that makes this an identity decision rather than housekeeping. Taken
 * deliberately by the owner on 2026-08-06.
 *
 * Two deliberate choices about the shape of it:
 *
 * **The default threshold is long — 365 days.** This is destructive and
 * irreversible, so the default must not be able to surprise anyone. A year of
 * total silence is unambiguous. Tighten it with `INACTIVE_USER_MAX_AGE_DAYS`
 * once there is real usage data to argue from; a number chosen before launch
 * would be a guess enforced by deletion.
 *
 * **A pass is bounded.** Deleting an unbounded set would hold a write
 * transaction over the whole table while the server takes live traffic. Several
 * small passes get to the same place; there is no deadline here.
 *
 * `last_seen` is null until a first authenticated action, so the query falls
 * back to `created_at` — otherwise an account registered and abandoned, exactly
 * the kind worth reclaiming, would never qualify.
 */
const INACTIVE_USER_MAX_AGE_DAYS = Number(process.env.INACTIVE_USER_MAX_AGE_DAYS || 365)
const INACTIVE_USER_BATCH = Number(process.env.INACTIVE_USER_BATCH || 200)
const INACTIVE_USER_SWEEP_INTERVAL = 6 * 60 * 60 * 1000 // every six hours

if (INACTIVE_USER_MAX_AGE_DAYS < 30) {
  console.error(
    `FATAL ERROR: INACTIVE_USER_MAX_AGE_DAYS must be at least 30 (got ${INACTIVE_USER_MAX_AGE_DAYS}). ` +
      'A short threshold on an irreversible delete is a footgun, not a configuration.'
  )
  process.exit(1)
}

const inactiveUserTimer = setInterval(() => {
  const cutoff = Math.floor(Date.now() / 1000) - INACTIVE_USER_MAX_AGE_DAYS * 24 * 60 * 60
  const { users, fileIds } = database.purgeInactiveUsers(cutoff, INACTIVE_USER_BATCH)
  if (users.length === 0) return
  // Blobs do not cascade with their rows; unlink them or they are unreachable
  // files nobody ever reclaims.
  if (fileIds.length > 0) void deleteFileBlobs(fileIds)
  console.log(
    `Reclaimed ${users.length} account(s) inactive for over ${INACTIVE_USER_MAX_AGE_DAYS} days; usernames released`
  )
}, INACTIVE_USER_SWEEP_INTERVAL)
inactiveUserTimer.unref()

// Purge expired invite tokens every 10 minutes
const inviteCleanupTimer = setInterval(
  () => {
    const purgedInvites = database.deleteExpiredInviteTokens(Math.floor(Date.now() / 1000))
    if (purgedInvites > 0) {
      console.log(`Purged ${purgedInvites} expired invite token(s)`)
    }
  },
  10 * 60 * 1000
)
inviteCleanupTimer.unref()

// Graceful shutdown
const SHUTDOWN_TIMEOUT_MS = 5000

const shutdown = (signal: string) => {
  console.log(`${signal} received, shutting down...`)

  // Force exit if graceful shutdown takes too long
  const forceTimer = setTimeout(() => {
    console.error('Graceful shutdown timed out, forcing exit')
    process.exit(1)
  }, SHUTDOWN_TIMEOUT_MS)
  forceTimer.unref()

  server.close(() => {
    database.close()
    console.log('Server closed')
    process.exit(0)
  })
}

process.on('SIGTERM', () => shutdown('SIGTERM'))
process.on('SIGINT', () => shutdown('SIGINT'))

process.on('unhandledRejection', reason => {
  console.error(
    'Unhandled promise rejection:',
    reason instanceof Error ? reason.message : String(reason)
  )
})

process.on('uncaughtException', err => {
  console.error('Uncaught exception:', err instanceof Error ? err.message : String(err))
  shutdown('uncaughtException')
})
