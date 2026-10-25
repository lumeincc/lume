// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Zod schemas for /groups routes.
 */

import { z } from 'zod'
import { UuidSchema } from './common'

export const GroupNameSchema = z
  .string()
  .trim()
  .min(1, 'Group name required')
  .max(64, 'Group name max 64 chars')

// POST /groups/create
export const CreateGroupBodySchema = z.object({
  name: GroupNameSchema,
  memberIds: z.array(UuidSchema).min(1, 'At least 1 member required').max(50, 'Max 50 members'),
})

// GET/DELETE /groups/:groupId
export const GroupIdParamSchema = z.object({
  groupId: UuidSchema,
})

// POST /groups/:groupId/members
export const AddMemberBodySchema = z.object({
  userId: UuidSchema,
})

// DELETE /groups/:groupId/members/:userId
export const GroupMemberParamSchema = z.object({
  groupId: UuidSchema,
  userId: UuidSchema,
})
