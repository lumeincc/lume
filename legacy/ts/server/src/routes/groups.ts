// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { Router, Request, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'
import rateLimit from 'express-rate-limit'

import database from '../db/database'
import { requireSignature } from '../middleware/auth'
import { validateBody, validateParams } from '../middleware/validate'
import {
  CreateGroupBodySchema,
  GroupIdParamSchema,
  AddMemberBodySchema,
  GroupMemberParamSchema,
} from '../schemas/groups'

const router = Router()

const groupRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `group:${req.user.userId}`
    const identityKey = req.user?.identityKey
    if (identityKey) {
      const user = database.getUserByIdentityKey(identityKey)
      if (user) return `group:${user.id}`
    }
    return `group:ip:${req.ip || '127.0.0.1'}`
  },
})

const groupReadRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `group-read:${req.user.userId}`
    const identityKey = req.user?.identityKey
    if (identityKey) {
      const user = database.getUserByIdentityKey(identityKey)
      if (user) return `group-read:${user.id}`
    }
    return `group-read:ip:${req.ip || '127.0.0.1'}`
  },
})

function getSignerUser(req: Request) {
  if (req.user?.userId) return database.getUserById(req.user.userId)
  return req.user?.identityKey ? database.getUserByIdentityKey(req.user.identityKey) : undefined
}

// POST /groups/create
router.post(
  '/create',
  requireSignature,
  groupRateLimit,
  validateBody(CreateGroupBodySchema),
  (req: Request, res: Response) => {
    try {
      const signer = getSignerUser(req)
      if (!signer) {
        res.status(403).json({ error: 'Unauthorized' })
        return
      }

      const { name, memberIds } = req.body as { name: string; memberIds: string[] }

      // Row cap: bound how many groups a single user can create. SEC-20260621-020.
      const MAX_GROUPS_PER_USER = Number(process.env.MAX_GROUPS_PER_USER) || 100
      if (database.countGroupsByCreator(signer.id) >= MAX_GROUPS_PER_USER) {
        res.status(429).json({ error: 'Group limit reached' })
        return
      }

      const groupId = uuidv4()
      database.createGroup(groupId, name.trim(), signer.id)

      // Add other members — batch-validate all IDs in one query. Honour
      // `discoverable`: a non-discoverable user must not be added to a group by
      // someone else, since GET /groups/:id would then disclose their username to
      // co-members without their consent (invariant 9). Owner decision (Bogdan).
      // SEC-20260721-023.
      const otherIds = memberIds.filter(id => id !== signer.id)
      const validUsers = database.getUsersByIds(otherIds)
      const validIds = new Set(validUsers.filter(u => u.discoverable).map(u => u.id))
      for (const id of otherIds) {
        if (validIds.has(id)) {
          database.addGroupMember(groupId, id)
        }
      }

      // Return the full persisted group (incl. creator_id/created_at) so the
      // client can validate it against GroupDataSchema. SEC-20260621-007.
      const group = database.getGroupById(groupId)
      const members = database.getGroupMembers(groupId)
      res.status(201).json({ ...group, members })
    } catch (error) {
      console.error('Create group error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to create group' })
    }
  }
)

// GET /groups — list user's groups
router.get('/', requireSignature, groupReadRateLimit, (req: Request, res: Response) => {
  try {
    const signer = getSignerUser(req)
    if (!signer) {
      res.status(403).json({ error: 'Unauthorized' })
      return
    }

    const groups = database.getUserGroups(signer.id)
    const groupIds = groups.map(g => g.id)
    const membersByGroup = database.getGroupMembersForGroups(groupIds)
    const result = groups.map(g => ({
      ...g,
      members: membersByGroup[g.id] ?? [],
    }))

    res.json({ groups: result })
  } catch (error) {
    console.error('List groups error:', error instanceof Error ? error.message : String(error))
    res.status(500).json({ error: 'Failed to list groups' })
  }
})

// GET /groups/:groupId
router.get(
  '/:groupId',
  requireSignature,
  groupReadRateLimit,
  validateParams(GroupIdParamSchema),
  (req: Request, res: Response) => {
    try {
      const groupId = req.params.groupId!

      const signer = getSignerUser(req)
      if (!signer) {
        res.status(403).json({ error: 'Unauthorized' })
        return
      }

      const group = database.getGroupById(groupId)
      if (!group) {
        res.status(404).json({ error: 'Group not found' })
        return
      }

      const members = database.getGroupMembers(groupId)
      const isMember = members.some(m => m.user_id === signer.id)
      if (!isMember) {
        res.status(403).json({ error: 'Not a member of this group' })
        return
      }

      res.json({ ...group, members })
    } catch (error) {
      console.error('Get group error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to get group' })
    }
  }
)

// POST /groups/:groupId/members — add a member
router.post(
  '/:groupId/members',
  requireSignature,
  groupRateLimit,
  validateParams(GroupIdParamSchema),
  validateBody(AddMemberBodySchema),
  (req: Request, res: Response) => {
    try {
      const groupId = req.params.groupId!

      const signer = getSignerUser(req)
      if (!signer) {
        res.status(403).json({ error: 'Unauthorized' })
        return
      }

      const group = database.getGroupById(groupId)
      if (!group) {
        res.status(404).json({ error: 'Group not found' })
        return
      }

      const members = database.getGroupMembers(groupId)
      const signerMember = members.find(m => m.user_id === signer.id)
      if (!signerMember || signerMember.role !== 'admin') {
        res.status(403).json({ error: 'Only admins can add members' })
        return
      }

      if (members.length >= 50) {
        res.status(400).json({ error: 'Group is full (max 50 members)' })
        return
      }

      const { userId } = req.body as { userId: string }

      const targetUser = database.getUserById(userId)
      // Non-discoverable users are treated as not-found here, so they cannot be
      // added to a group by others (invariant 9) — same rule as /profile.
      // Owner decision (Bogdan). SEC-20260721-023.
      if (!targetUser || !targetUser.discoverable) {
        res.status(404).json({ error: 'User not found' })
        return
      }

      database.addGroupMember(groupId, userId)
      res.json({ ok: true, members: database.getGroupMembers(groupId) })
    } catch (error) {
      console.error(
        'Add group member error:',
        error instanceof Error ? error.message : String(error)
      )
      res.status(500).json({ error: 'Failed to add member' })
    }
  }
)

// DELETE /groups/:groupId/members/:userId — remove a member or leave
router.delete(
  '/:groupId/members/:userId',
  requireSignature,
  groupRateLimit,
  validateParams(GroupMemberParamSchema),
  (req: Request, res: Response) => {
    try {
      const groupId = req.params.groupId!
      const userId = req.params.userId!

      const signer = getSignerUser(req)
      if (!signer) {
        res.status(403).json({ error: 'Unauthorized' })
        return
      }

      const group = database.getGroupById(groupId)
      if (!group) {
        res.status(404).json({ error: 'Group not found' })
        return
      }

      const members = database.getGroupMembers(groupId)
      const signerMember = members.find(m => m.user_id === signer.id)
      if (!signerMember) {
        res.status(403).json({ error: 'Not a member' })
        return
      }

      // Anyone can leave (remove themselves), admins can remove others
      if (userId !== signer.id && signerMember.role !== 'admin') {
        res.status(403).json({ error: 'Only admins can remove members' })
        return
      }

      database.removeGroupMember(groupId, userId)

      // If no members left, delete the group
      const remaining = database.getGroupMembers(groupId)
      if (remaining.length === 0) {
        database.deleteGroup(groupId)
        res.json({ ok: true, deleted: true })
        return
      }

      // If the admin left, promote the next member
      const nextMember = remaining[0]
      if (userId === group.creator_id && nextMember && !remaining.some(m => m.role === 'admin')) {
        database.removeGroupMember(groupId, nextMember.user_id)
        database.addGroupMember(groupId, nextMember.user_id, 'admin')
      }

      res.json({ ok: true, members: database.getGroupMembers(groupId) })
    } catch (error) {
      console.error(
        'Remove group member error:',
        error instanceof Error ? error.message : String(error)
      )
      res.status(500).json({ error: 'Failed to remove member' })
    }
  }
)

export default router
