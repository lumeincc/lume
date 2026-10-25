// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { Router, type Request, type Response } from 'express'
import { requireSignature } from '../middleware/auth'
import { validateBody, validateParams } from '../middleware/validate'
import { ProfileParamSchema, UpdateProfileBodySchema } from '../schemas/profile'
import database from '../db/database'
import rateLimit from 'express-rate-limit'

const router = Router()

const profileLimiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `profile:${req.user.userId}`
    const identityKey = req.user?.identityKey
    if (identityKey) {
      const user = database.getUserByIdentityKey(identityKey)
      if (user) return `profile:${user.id}`
    }
    return `profile:ip:${req.ip || '127.0.0.1'}`
  },
})

/** GET /profile/:userId — get user profile */
router.get(
  '/:userId',
  requireSignature,
  profileLimiter,
  validateParams(ProfileParamSchema),
  (req: Request, res: Response) => {
    const userId = req.params.userId!
    const user = database.getUserById(userId)
    if (!user) {
      res.status(404).json({ error: 'User not found' })
      return
    }

    if (!user.discoverable && req.user?.identityKey !== user.identity_key) {
      res.status(404).json({ error: 'User not found' })
      return
    }

    res.setHeader('Cache-Control', 'private, no-cache')
    res.json({
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      avatarFileId: user.avatar_file_id,
      discoverable: !!user.discoverable,
    })
  }
)

/** PUT /profile/:userId — update own profile */
router.put(
  '/:userId',
  requireSignature,
  profileLimiter,
  validateParams(ProfileParamSchema),
  validateBody(UpdateProfileBodySchema),
  (req: Request, res: Response) => {
    const userId = req.params.userId!
    const { displayName, avatarFileId } = req.body as {
      displayName?: string | null
      avatarFileId?: string | null
    }

    const user = database.getUserById(userId)
    if (!user) {
      res.status(404).json({ error: 'User not found' })
      return
    }

    if (req.user?.identityKey !== user.identity_key) {
      res.status(403).json({ error: "Cannot edit another user's profile" })
      return
    }

    const name = displayName !== undefined ? displayName : user.display_name
    const avatar = avatarFileId !== undefined ? avatarFileId : user.avatar_file_id

    database.setProfile(userId, name ?? null, avatar ?? null)

    res.json({
      id: user.id,
      username: user.username,
      displayName: name,
      avatarFileId: avatar,
      discoverable: !!user.discoverable,
    })
  }
)

export default router
