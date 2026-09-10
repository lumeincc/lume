// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { Router, Request, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import nacl from 'tweetnacl'
import { decodeBase64 } from 'tweetnacl-util'
import rateLimit from 'express-rate-limit'

import database from '../db/database'
import { requireSignature } from '../middleware/auth'
import { validateBody, validateParams } from '../middleware/validate'
import {
  RegisterBodySchema,
  BundleBodySchema,
  UsernameParamSchema,
  UploadPrekeysBodySchema,
  UpdateKeysBodySchema,
  UserIdParamSchema,
  SessionBodySchema,
  BlockBodySchema,
  InviteTokenBodySchema,
  InviteTokenParamSchema,
  DiscoverableBodySchema,
} from '../schemas/auth'

const router = Router()
const LOG_SECURITY = process.env.LOG_SECURITY === '1'

function audit(event: string, details: Record<string, unknown>) {
  if (!LOG_SECURITY) return
  const safeDetails = JSON.stringify(details, (_k, v) =>
    typeof v === 'string' && v.length > 64 ? `${v.slice(0, 32)}…` : v
  )
  console.log(`[audit] ${event} ${safeDetails}`)
}

// === Rate Limiting ==========================================================

/**
 * Registration is the one endpoint that creates unbounded state.
 *
 * Every account is a `users` row plus twenty one-time prekeys. They are pruned
 * by the inactivity sweep in `index.ts`, which is the table's actual bound; the
 * ephemeral disk on Render's free plan also wipes it, but that is an accident of
 * hosting and would disappear the day the plan changes.
 *
 * The window was ten minutes, so one address could mint 180 accounts an hour,
 * or 4,320 a day. Raised to an hour for the same allowance, cutting that
 * sixfold while staying generous enough for a shared exit — a café or a campus
 * behind one NAT can still register thirty people in an hour, which is far more
 * than any real hour of signups.
 *
 * Inactive accounts do expire — the question was open when this comment was
 * written and has since been decided: the sweep releases the username, and a
 * released username may be reissued. That is an identity decision rather than
 * housekeeping, and the reasoning for why reissue is safe here (identity is the
 * key pair, not the name — a new holder cannot impersonate the old one, and the
 * safety number changes) lives in `docs/DDOS.md`, not in a rate-limiter.
 */
const registerRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => `ip:${req.ip || '127.0.0.1'}`,
})

/**
 * Fleet-wide ceiling on *successful* account creation. SEC-20260721-001.
 *
 * This bucket is shared by every caller, which is the point of a fleet guard and
 * also its hazard: whatever can fill it can deny registration to everyone. Three
 * things keep that from being reachable by one source.
 *
 * 1. It counts successes only. `express-rate-limit` counts requests by default,
 *    so the previous version could be exhausted with junk bodies — no valid
 *    signature, no unused username, no work. `skipFailedRequests` means a 4xx
 *    costs nothing, so filling this now requires that many genuinely completed
 *    registrations, each with a distinct username and a valid Ed25519 signature.
 *
 * 2. The ceiling sits above what one address can produce. The per-IP limiter
 *    allows 180/hour; at 600 a single address would need well over three hours
 *    of uninterrupted *successful* registration to exhaust it, and would trip
 *    its own per-IP limit throughout. The previous 100/hour was *below* one
 *    address's allowance, which is what made a single IP sufficient.
 *
 * 3. Rebind does not pass through it at all — see `skip` below.
 *
 * Raise this if organic signup ever approaches it; it is a guard against mass
 * automated creation, not a product limit.
 */
const globalRegisterRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 600,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (): string => 'global:register',
  skipFailedRequests: true,
  /**
   * Identity rebind runs through this same route (Branch A) but is a recovery
   * path for an account that already exists — it creates nothing, so a ceiling
   * on account creation must not apply to it. A user whose server row was reset
   * has to be able to re-bind even while the fleet guard is saturated.
   *
   * Signed headers are the cheapest available proxy for "not a new account".
   * They are not proof — the handler still runs `requireSignature` and still
   * checks the identity key against the stored row — but a request without them
   * cannot reach Branch A, so skipping on their presence never lets an actual
   * registration past this limiter. The per-IP limiter still applies.
   */
  skip: (req: Request): boolean =>
    Boolean(req.headers['x-lume-identity-key'] && req.headers['x-lume-signature']),
})

const usernameCheckRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => `ip:${req.ip || '127.0.0.1'}`,
})

const sessionRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `uid:${req.user.userId}`
    const identityKey = req.user?.identityKey
    if (identityKey) {
      const user = database.getUserByIdentityKey(identityKey)
      if (user) return `uid:${user.id}`
    }
    return `ip:${req.ip || '127.0.0.1'}`
  },
})

// Authenticated write endpoints (prekey rotation, uploads, etc.)
const keysRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `uid:${req.user.userId}`
    const identityKey = req.user?.identityKey
    if (identityKey) {
      const user = database.getUserByIdentityKey(identityKey)
      if (user) return `uid:${user.id}`
    }
    return `ip:${req.ip || '127.0.0.1'}`
  },
})

// === Response Types =========================================================

interface GetUserResponse {
  id: string
  username: string
  identityKey: string
  exchangeKey?: string
  exchangeIdentityKey?: string
  signedPrekey: string
  signedPrekeySignature: string
  oneTimePrekey?: string
}

// === Helpers ================================================================

function verifySignature(signedPrekey: string, signature: string, identityKey: string): boolean {
  try {
    const messageBytes = decodeBase64(signedPrekey)
    const signatureBytes = decodeBase64(signature)
    const publicKeyBytes = decodeBase64(identityKey)
    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes)
  } catch {
    return false
  }
}

// === Routes =================================================================

// POST /auth/register
router.post(
  '/register',
  registerRateLimit,
  globalRegisterRateLimit,
  validateBody(RegisterBodySchema),
  async (req: Request, res: Response) => {
    try {
      const body = req.body as import('../schemas/auth').RegisterBody

      // Detect signed headers — if present, run requireSignature inside the handler
      const hasSignedHeaders = Boolean(
        req.headers['x-lume-identity-key'] && req.headers['x-lume-signature']
      )

      if (hasSignedHeaders) {
        await new Promise<void>((resolve, reject) => {
          requireSignature(req, res, (err?: unknown) => (err ? reject(err) : resolve()))
        })
        if (res.headersSent) return
      }

      const existingUser = database.getUserByUsername(body.username)

      // Branch A: rebind — existing row, signed, identityKey matches
      if (
        existingUser &&
        hasSignedHeaders &&
        req.user?.identityKey === body.identityKey &&
        existingUser.identity_key === body.identityKey
      ) {
        if (!verifySignature(body.signedPrekey, body.signedPrekeySignature, body.identityKey)) {
          res.status(400).json({ error: 'Invalid signed prekey signature' })
          return
        }

        database.setSignedPrekey(existingUser.id, body.signedPrekey, body.signedPrekeySignature)
        database.replacePrekeys(existingUser.id, body.oneTimePrekeys ?? [])

        if (
          body.exchangeIdentityKey &&
          body.exchangeIdentityKey !== existingUser.exchange_identity_key
        ) {
          database.updateExchangeIdentityKey(existingUser.id, body.exchangeIdentityKey)
        }

        res.status(201).json({
          id: existingUser.id,
          username: existingUser.username,
          message: 'Rebind successful',
        })
        audit('rebind', { userId: existingUser.id, username: existingUser.username })
        return
      }

      // Branch B: conflict — existing row, different identityKey or unsigned
      if (existingUser) {
        res.status(409).json({ error: 'Username already taken' })
        return
      }

      // Branch C: no existing row — new registration
      if (!verifySignature(body.signedPrekey, body.signedPrekeySignature, body.identityKey)) {
        res.status(400).json({ error: 'Invalid signed prekey signature' })
        return
      }

      // If signed, assert body.identityKey matches the signing key
      if (hasSignedHeaders && req.user!.identityKey !== body.identityKey) {
        res.status(403).json({ error: 'Identity key mismatch' })
        return
      }

      const userId = uuidv4()
      const exchangeIdentityKey = body.exchangeIdentityKey ?? body.signedPrekey

      database.createUser(
        userId,
        body.username,
        body.identityKey,
        exchangeIdentityKey,
        body.signedPrekey,
        body.signedPrekeySignature
      )

      if (body.oneTimePrekeys && body.oneTimePrekeys.length > 0) {
        database.addPrekeys(userId, body.oneTimePrekeys)
      }

      res.status(201).json({
        id: userId,
        username: body.username,
        message: 'Registration successful',
      })
      audit('register', { userId, username: body.username })
    } catch (error) {
      if (error instanceof Error) {
        if (error.message.includes('UNIQUE constraint failed')) {
          res.status(409).json({ error: 'Registration conflict. Try a different username.' })
          return
        }
      }
      console.error('Registration error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to register account' })
    }
  }
)

// GET /auth/user/:username — requires authentication to prevent username enumeration
router.get(
  '/user/:username',
  requireSignature,
  usernameCheckRateLimit,
  validateParams(UsernameParamSchema),
  (req: Request, res: Response) => {
    try {
      const username = req.params.username!.trim()

      const user = database.getUserByUsername(username)
      if (!user) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      // Non-discoverable users are hidden from username lookup (except self-lookup)
      const isSelf = req.user?.identityKey === user.identity_key
      if (!user.discoverable && !isSelf) {
        res.status(404).json({ error: 'User not found' })
        return
      }
      const exchangeIdentityKey = user.exchange_identity_key || user.signed_prekey

      const response: GetUserResponse = {
        id: user.id,
        username: user.username,
        identityKey: user.identity_key,
        exchangeKey: exchangeIdentityKey,
        exchangeIdentityKey,
        signedPrekey: user.signed_prekey,
        signedPrekeySignature: user.signed_prekey_signature,
      }

      res.json(response)
    } catch (error) {
      console.error('Get user error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to retrieve user profile' })
    }
  }
)

// Prekey bundle rate limit — tighter per-requester limit to prevent prekey exhaustion.
const bundleRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 10, // max 10 bundle fetches per minute per requester
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `bundle:${req.user.userId}`
    const identityKey = req.user?.identityKey
    if (identityKey) {
      const user = database.getUserByIdentityKey(identityKey)
      if (user) return `bundle:${user.id}`
    }
    return `bundle:ip:${req.ip || '127.0.0.1'}`
  },
})

// POST /auth/bundle
// Returns a prekey bundle and consumes one one-time prekey (if available).
router.post(
  '/bundle',
  requireSignature,
  bundleRateLimit,
  validateBody(BundleBodySchema),
  (req: Request, res: Response) => {
    try {
      const { username } = req.body as { username: string }

      // Prevent requesting your own bundle (no reason to consume your own prekeys).
      const requester = req.user?.userId ? database.getUserById(req.user.userId) : undefined

      const user = database.getUserByUsername(username)
      if (!user) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      // Non-discoverable users can't be found via username bundle (except self)
      const isSelfBundle = requester && requester.id === user.id
      if (!user.discoverable && !isSelfBundle) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      if (requester && requester.id === user.id) {
        res.status(400).json({ error: 'Cannot request your own bundle' })
        return
      }

      const exchangeIdentityKey = user.exchange_identity_key || user.signed_prekey
      const oneTimePrekey = database.consumePrekey(user.id)

      const response: GetUserResponse = {
        id: user.id,
        username: user.username,
        identityKey: user.identity_key,
        exchangeKey: exchangeIdentityKey,
        exchangeIdentityKey,
        signedPrekey: user.signed_prekey,
        signedPrekeySignature: user.signed_prekey_signature,
      }

      if (oneTimePrekey) {
        response.oneTimePrekey = oneTimePrekey
      }

      res.json(response)
      audit('bundle_consume', {
        requesterId: requester?.id,
        targetId: user.id,
        hadOPK: !!oneTimePrekey,
      })
    } catch (error) {
      console.error('Get bundle error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to retrieve prekey bundle' })
    }
  }
)

// GET /auth/check/:username
// Auth: none. Username availability must be checkable during setup, before the
// client has any keys to sign with (PROTOCOL.md: Auth required = No). Rate limited
// per IP. A taken username is reported unavailable regardless of `discoverable`,
// so this endpoint agrees with /auth/register — see the note at the response for
// why hiding it here leaked more than it protected. SEC-20260721-015.
router.get(
  '/check/:username',
  usernameCheckRateLimit,
  validateParams(UsernameParamSchema),
  (req: Request, res: Response) => {
    try {
      const username = req.params.username!.trim()
      const user = database.getUserByUsername(username)
      // A taken username is unavailable regardless of `discoverable`, matching
      // /auth/register. Username uniqueness is inherently observable (register
      // 409s on a duplicate), so reporting a non-discoverable name as "available"
      // only created an oracle via the contradiction between the two endpoints.
      // `discoverable` still governs profile lookup and existence via /profile.
      // Owner decision (Bogdan). SEC-20260721-015.
      res.json({ available: !user })
    } catch (error) {
      console.error('Check username error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to check username availability' })
    }
  }
)

// POST /auth/prekeys
router.post(
  '/prekeys',
  requireSignature,
  keysRateLimit,
  validateBody(UploadPrekeysBodySchema),
  (req: Request, res: Response) => {
    try {
      const { userId, prekeys } = req.body as {
        userId: string
        prekeys: Array<{ id: string; publicKey: string }>
      }

      const user = database.getUserById(userId)
      if (!user) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      if (user.identity_key !== req.user?.identityKey) {
        res.status(403).json({ error: 'Unauthorized: Identity key mismatch' })
        return
      }

      // Enforce total prekey cap to prevent storage abuse
      const MAX_PREKEYS = 1000
      const currentCount = database.getPrekeyCount(userId)
      if (currentCount + prekeys.length > MAX_PREKEYS) {
        res.status(400).json({
          error: `Prekey limit exceeded. Max ${MAX_PREKEYS}, current ${currentCount}, attempted +${prekeys.length}`,
        })
        return
      }

      database.addPrekeys(userId, prekeys)

      const count = database.getPrekeyCount(userId)
      res.json({
        message: 'Prekeys uploaded',
        totalPrekeys: count,
      })
    } catch (error) {
      console.error('Upload prekeys error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to upload prekeys' })
    }
  }
)

// POST /auth/keys
router.post(
  '/keys',
  requireSignature,
  keysRateLimit,
  validateBody(UpdateKeysBodySchema),
  (req: Request, res: Response) => {
    try {
      const { userId, signedPrekey, signedPrekeySignature } = req.body as {
        userId: string
        signedPrekey: string
        signedPrekeySignature: string
      }

      const user = database.getUserById(userId)
      if (!user) {
        res.status(404).json({ error: 'User not found' })
        return
      }
      if (user.identity_key !== req.user?.identityKey) {
        res.status(403).json({ error: 'Unauthorized: Identity key mismatch' })
        return
      }
      if (!verifySignature(signedPrekey, signedPrekeySignature, user.identity_key)) {
        res.status(400).json({ error: 'Invalid signed prekey signature' })
        return
      }

      database.setSignedPrekey(userId, signedPrekey, signedPrekeySignature)
      res.json({ message: 'Signed prekey updated' })
    } catch (error) {
      console.error(
        'Update signed prekey error:',
        error instanceof Error ? error.message : String(error)
      )
      res.status(500).json({ error: 'Failed to update signed prekey' })
    }
  }
)

// DELETE /auth/user/:userId
router.delete(
  '/user/:userId',
  requireSignature,
  keysRateLimit,
  validateParams(UserIdParamSchema),
  (req: Request, res: Response) => {
    try {
      const userId = req.params.userId!

      const user = database.getUserById(userId)
      if (!user) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      if (user.identity_key !== req.user?.identityKey) {
        res.status(403).json({ error: 'Unauthorized: Identity key mismatch' })
        return
      }

      database.deleteUser(userId)
      res.json({ message: 'Account deleted' })
      audit('delete_user', { userId })
    } catch (error) {
      console.error('Delete user error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to delete account' })
    }
  }
)

// POST /auth/session
router.post(
  '/session',
  requireSignature,
  sessionRateLimit,
  validateBody(SessionBodySchema),
  (req: Request, res: Response) => {
    try {
      const { userId } = req.body as { userId: string }

      const user = database.getUserById(userId)
      if (!user) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      if (user.identity_key !== req.user?.identityKey) {
        res.status(403).json({ error: 'Identity key mismatch' })
        return
      }

      const token = jwt.sign({ sub: userId }, process.env.WS_JWT_SECRET as string, {
        algorithm: 'HS256',
        expiresIn: '10m',
        issuer: 'lume',
        audience: 'lume-ws',
      })

      res.json({ token, expiresIn: 600 })
      audit('session_issue', { userId })
    } catch (error) {
      console.error('Session error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to create session' })
    }
  }
)

// === Block / Unblock ========================================================

// POST /auth/block
router.post(
  '/block',
  requireSignature,
  keysRateLimit,
  validateBody(BlockBodySchema),
  (req: Request, res: Response) => {
    try {
      const { blockedId } = req.body as { blockedId: string }

      const signerId = req.user?.userId
      if (!signerId) {
        res.status(403).json({ error: 'Unauthorized' })
        return
      }

      if (signerId === blockedId) {
        res.status(400).json({ error: 'Cannot block yourself' })
        return
      }

      const targetUser = database.getUserById(blockedId)
      if (!targetUser) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      // Row cap: bound the block list per user. SEC-20260621-020.
      const MAX_BLOCKED_PER_USER = Number(process.env.MAX_BLOCKED_PER_USER) || 1000
      if (database.countBlockedByUser(signerId) >= MAX_BLOCKED_PER_USER) {
        res.status(429).json({ error: 'Block list limit reached' })
        return
      }

      database.blockUser(signerId, blockedId)
      audit('block_user', { blockerId: signerId, blockedId })
      res.json({ ok: true })
    } catch (error) {
      console.error('Block error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to block user' })
    }
  }
)

// POST /auth/unblock
router.post(
  '/unblock',
  requireSignature,
  keysRateLimit,
  validateBody(BlockBodySchema),
  (req: Request, res: Response) => {
    try {
      const { blockedId } = req.body as { blockedId: string }

      const signerId = req.user?.userId
      if (!signerId) {
        res.status(403).json({ error: 'Unauthorized' })
        return
      }

      database.unblockUser(signerId, blockedId)
      audit('unblock_user', { blockerId: signerId, blockedId })
      res.json({ ok: true })
    } catch (error) {
      console.error('Unblock error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to unblock user' })
    }
  }
)

// GET /auth/blocked
router.get('/blocked', requireSignature, keysRateLimit, (req: Request, res: Response) => {
  try {
    const signerId = req.user?.userId
    if (!signerId) {
      res.status(403).json({ error: 'Unauthorized' })
      return
    }

    const blockedIds = database.getBlockedUsers(signerId)
    res.json({ blockedIds })
  } catch (error) {
    console.error(
      'Get blocked users error:',
      error instanceof Error ? error.message : String(error)
    )
    res.status(500).json({ error: 'Failed to retrieve blocked users list' })
  }
})

// === Invite Tokens ===========================================================

const INVITE_TOKEN_TTL_SEC = 24 * 60 * 60 // 24 hours
const MAX_INVITE_TOKENS_PER_USER = 5

const inviteRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `invite:${req.user.userId}`
    return `invite:ip:${req.ip || '127.0.0.1'}`
  },
})

// POST /auth/invite-token
router.post(
  '/invite-token',
  requireSignature,
  inviteRateLimit,
  validateBody(InviteTokenBodySchema),
  (req: Request, res: Response) => {
    try {
      const { userId } = req.body as { userId: string }

      const user = database.getUserById(userId)
      if (!user) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      if (user.identity_key !== req.user?.identityKey) {
        res.status(403).json({ error: 'Unauthorized: Identity key mismatch' })
        return
      }

      // Enforce per-user token cap
      const tokenCount = database.getUserInviteTokenCount(userId)
      if (tokenCount >= MAX_INVITE_TOKENS_PER_USER) {
        // Clean up expired first, then re-check
        const nowSec = Math.floor(Date.now() / 1000)
        database.deleteExpiredInviteTokens(nowSec)
        const refreshedCount = database.getUserInviteTokenCount(userId)
        if (refreshedCount >= MAX_INVITE_TOKENS_PER_USER) {
          res.status(400).json({ error: 'Too many active invite tokens' })
          return
        }
      }

      const id = uuidv4()
      const token = crypto.randomBytes(16).toString('base64url')
      const nowSec = Math.floor(Date.now() / 1000)
      const expiresAt = nowSec + INVITE_TOKEN_TTL_SEC

      database.createInviteToken(id, userId, token, expiresAt)

      res.status(201).json({ token, expiresAt })
      audit('invite_token_create', { userId, expiresAt })
    } catch (error) {
      console.error(
        'Create invite token error:',
        error instanceof Error ? error.message : String(error)
      )
      res.status(500).json({ error: 'Failed to create invite token' })
    }
  }
)

// GET /auth/resolve-invite/:token
router.get(
  '/resolve-invite/:token',
  requireSignature,
  inviteRateLimit,
  validateParams(InviteTokenParamSchema),
  (req: Request, res: Response) => {
    try {
      const tokenValue = req.params.token!

      const invite = database.getInviteByToken(tokenValue)
      if (!invite) {
        res.status(404).json({ error: 'Invite not found or expired' })
        return
      }

      const nowSec = Math.floor(Date.now() / 1000)
      if (invite.expires_at < nowSec) {
        res.status(410).json({ error: 'Invite token has expired' })
        return
      }

      const user = database.getUserById(invite.user_id)
      if (!user) {
        res.status(404).json({ error: 'User no longer exists' })
        return
      }

      // Prevent resolving your own invite
      if (req.user?.userId === user.id) {
        res.status(400).json({ error: 'Cannot resolve your own invite' })
        return
      }

      const exchangeIdentityKey = user.exchange_identity_key || user.signed_prekey

      res.json({
        id: user.id,
        username: user.username,
        identityKey: user.identity_key,
        exchangeKey: exchangeIdentityKey,
        exchangeIdentityKey,
        signedPrekey: user.signed_prekey,
        signedPrekeySignature: user.signed_prekey_signature,
        expiresAt: invite.expires_at,
      })
    } catch (error) {
      console.error('Resolve invite error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to resolve invite token' })
    }
  }
)

// PUT /auth/discoverable
router.put(
  '/discoverable',
  requireSignature,
  keysRateLimit,
  validateBody(DiscoverableBodySchema),
  (req: Request, res: Response) => {
    try {
      const { userId, discoverable } = req.body as { userId: string; discoverable: boolean }

      const user = database.getUserById(userId)
      if (!user) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      if (user.identity_key !== req.user?.identityKey) {
        res.status(403).json({ error: 'Unauthorized: Identity key mismatch' })
        return
      }

      database.setDiscoverable(userId, discoverable)

      res.json({ ok: true, discoverable })
      audit('discoverable_toggle', { userId, discoverable })
    } catch (error) {
      console.error(
        'Discoverable toggle error:',
        error instanceof Error ? error.message : String(error)
      )
      res.status(500).json({ error: 'Failed to update discoverability' })
    }
  }
)

export default router
