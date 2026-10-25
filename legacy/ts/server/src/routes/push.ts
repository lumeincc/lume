// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { Router, type Request, type Response } from 'express'
import { requireSignature } from '../middleware/auth'
import { validateBody } from '../middleware/validate'
import { SubscribeBodySchema, UnsubscribeBodySchema } from '../schemas/push'
import database from '../db/database'
import { getVapidPublicKey, isWebPushEnabled } from '../services/pushService'
import rateLimit from 'express-rate-limit'

const router = Router()

const pushLimiter = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `push:${req.user.userId}`
    const identityKey = req.user?.identityKey
    if (identityKey) {
      const user = database.getUserByIdentityKey(identityKey)
      if (user) return `push:${user.id}`
    }
    return `push:ip:${req.ip || '127.0.0.1'}`
  },
})

/** GET /push/vapid-key — public VAPID key for client subscription */
router.get('/vapid-key', pushLimiter, (_req: Request, res: Response) => {
  if (!isWebPushEnabled()) {
    res.status(503).json({ error: 'Push notifications not configured' })
    return
  }
  res.json({ vapidPublicKey: getVapidPublicKey() })
})

/** POST /push/subscribe — save push subscription */
router.post(
  '/subscribe',
  requireSignature,
  pushLimiter,
  validateBody(SubscribeBodySchema),
  (req: Request, res: Response) => {
    if (!isWebPushEnabled()) {
      res.status(503).json({ error: 'Push notifications not configured' })
      return
    }

    const { userId, subscription } = req.body as {
      userId: string
      subscription: { endpoint: string; keys: { p256dh: string; auth: string } }
    }

    const user = database.getUserById(userId)
    if (!user) {
      res.status(404).json({ error: 'User not found' })
      return
    }

    if (user.identity_key !== req.user?.identityKey) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }

    database.setPushToken(userId, JSON.stringify(subscription))
    res.json({ ok: true })
  }
)

/** POST /push/unsubscribe — remove push subscription */
router.post(
  '/unsubscribe',
  requireSignature,
  pushLimiter,
  validateBody(UnsubscribeBodySchema),
  (req: Request, res: Response) => {
    const { userId } = req.body as { userId: string }

    const user = database.getUserById(userId)
    if (!user) {
      res.status(404).json({ error: 'User not found' })
      return
    }

    if (user.identity_key !== req.user?.identityKey) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }

    database.setPushToken(userId, '')
    res.json({ ok: true })
  }
)

export default router
