// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Zod schemas for /auth routes.
 */

import { z } from 'zod'
import {
  UuidSchema,
  UsernameSchema,
  IdentityKeySchema,
  SignatureSchema,
  SignedPrekeySchema,
  PrekeysArraySchema,
} from './common'

// POST /auth/register
export const RegisterBodySchema = z.object({
  username: UsernameSchema,
  identityKey: IdentityKeySchema,
  exchangeIdentityKey: IdentityKeySchema.optional(),
  signedPrekey: SignedPrekeySchema,
  signedPrekeySignature: SignatureSchema,
  oneTimePrekeys: z
    .array(z.object({ id: z.string().trim().min(1).max(128), publicKey: SignedPrekeySchema }))
    .max(1000)
    .optional(),
})
export type RegisterBody = z.infer<typeof RegisterBodySchema>

// POST /auth/bundle
export const BundleBodySchema = z.object({
  username: UsernameSchema,
})

// GET /auth/user/:username, GET /auth/check/:username
export const UsernameParamSchema = z.object({
  username: UsernameSchema,
})

// POST /auth/prekeys
export const UploadPrekeysBodySchema = z.object({
  userId: UuidSchema,
  prekeys: PrekeysArraySchema,
})

// POST /auth/keys
export const UpdateKeysBodySchema = z.object({
  userId: UuidSchema,
  signedPrekey: SignedPrekeySchema,
  signedPrekeySignature: SignatureSchema,
})

// DELETE /auth/user/:userId
export const UserIdParamSchema = z.object({
  userId: UuidSchema,
})

// POST /auth/session
export const SessionBodySchema = z.object({
  userId: UuidSchema,
})

// POST /auth/block, POST /auth/unblock
export const BlockBodySchema = z.object({
  blockedId: UuidSchema,
})

// POST /auth/invite-token
export const InviteTokenBodySchema = z.object({
  userId: UuidSchema,
})

// GET /auth/resolve-invite/:token
export const InviteTokenParamSchema = z.object({
  token: z.string().trim().min(1).max(128),
})

// PUT /auth/discoverable
export const DiscoverableBodySchema = z.object({
  userId: UuidSchema,
  discoverable: z.boolean(),
})
