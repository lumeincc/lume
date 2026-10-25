// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Zod schemas for validating server API responses.
 * Every response from the server is validated before use.
 */

import { z } from 'zod'
import { decodeBase64 } from 'tweetnacl-util'

// ── Primitives ──────────────────────────────────────────────

const UuidSchema = z
  .string()
  .trim()
  .regex(
    /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/,
    'Invalid UUID format'
  )
const UsernameSchema = z.string().min(3).max(32)

/**
 * Base64 key/signature validated by decoded byte length, mirroring the server's
 * `base64Key` (server/src/schemas/common.ts). The client is explicitly told not
 * to trust the server, so key material is checked to the same strictness here
 * before it reaches `decodeBase64` and the NaCl primitives. SEC-20260721-026.
 */
const base64Key = (expectedBytes = 32) =>
  z.string().refine(
    val => {
      try {
        return decodeBase64(val).length === expectedBytes
      } catch {
        return false
      }
    },
    { message: `Key must be exactly ${expectedBytes} bytes when decoded` }
  )

// ── Generic / status responses ──────────────────────────────

export const MessageResponseSchema = z.object({
  message: z.string(),
})

export const OkResponseSchema = z.object({
  ok: z.boolean(),
})

export const HealthResponseSchema = z.object({
  status: z.string(),
  timestamp: z.string(),
})

// ── Auth responses ──────────────────────────────────────────

export const UploadPrekeysResponseSchema = z.object({
  message: z.string(),
  totalPrekeys: z.number().int().nonnegative(),
})

export const RegisterResponseSchema = z.object({
  id: UuidSchema,
  username: UsernameSchema,
  message: z.string(),
})

export const CheckUsernameResponseSchema = z.object({
  available: z.boolean(),
  reason: z.string().optional(),
})

export const UserBundleSchema = z.object({
  id: UuidSchema,
  username: UsernameSchema,
  identityKey: base64Key(32),
  exchangeKey: base64Key(32).optional(),
  exchangeIdentityKey: base64Key(32).optional(),
  signedPrekey: base64Key(32),
  signedPrekeySignature: base64Key(64),
  oneTimePrekey: base64Key(32).optional(),
})

export const SessionResponseSchema = z.object({
  token: z.string().min(1),
  expiresIn: z.number().positive(),
})

export const BlockedUsersResponseSchema = z.object({
  blockedIds: z.array(UuidSchema),
})

// ── Messages responses ──────────────────────────────────────

export const SendMessageResponseSchema = z.object({
  messageId: UuidSchema,
  delivered: z.boolean(),
})

export const PendingMessageSchema = z.object({
  id: UuidSchema,
  senderId: UuidSchema,
  senderUsername: UsernameSchema,
  encryptedPayload: z.string().min(1),
  timestamp: z.number(),
})

export const PendingMessagesResponseSchema = z.object({
  messages: z.array(PendingMessageSchema),
  nextCursor: z.string().nullable().optional(),
  hasMore: z.boolean().optional(),
})

export const AcknowledgeResponseSchema = z.object({
  acknowledged: z.number().int().nonnegative(),
})

// ── Files responses ─────────────────────────────────────────

export const UploadFileResponseSchema = z.object({
  fileId: UuidSchema,
  size: z.number().positive(),
  expiresAt: z.number(),
})

export const DownloadFileResponseSchema = z.object({
  fileId: UuidSchema,
  data: z.string().min(1),
  mimeHint: z.string(),
  size: z.number(),
})

// ── Groups responses ────────────────────────────────────────

export const GroupMemberSchema = z.object({
  user_id: UuidSchema,
  username: UsernameSchema,
  role: z.string(),
})

export const GroupDataSchema = z.object({
  id: UuidSchema,
  name: z.string().min(1),
  creator_id: UuidSchema,
  created_at: z.number(),
  members: z.array(GroupMemberSchema),
})

export const GroupListResponseSchema = z.object({
  groups: z.array(GroupDataSchema),
})

export const AddMemberResponseSchema = z.object({
  ok: z.boolean(),
  members: z.array(GroupMemberSchema),
})

// Remove/leave returns either { ok, deleted } (group removed) or { ok, members }.
export const RemoveMemberResponseSchema = z.object({
  ok: z.boolean(),
  deleted: z.boolean().optional(),
  members: z.array(GroupMemberSchema).optional(),
})

// ── Profile responses ───────────────────────────────────────

export const ProfileDataSchema = z.object({
  id: UuidSchema,
  username: UsernameSchema,
  displayName: z.string().nullable(),
  avatarFileId: z.string().nullable(),
  discoverable: z.boolean().optional(),
})

// ── Invite token responses ──────────────────────────────────

export const InviteTokenResponseSchema = z.object({
  token: z.string().min(1),
  expiresAt: z.number().positive(),
})

export const ResolveInviteResponseSchema = z.object({
  id: UuidSchema,
  username: UsernameSchema,
  identityKey: base64Key(32),
  exchangeKey: base64Key(32).optional(),
  exchangeIdentityKey: base64Key(32).optional(),
  signedPrekey: base64Key(32),
  signedPrekeySignature: base64Key(64),
  expiresAt: z.number().positive(),
})

export const DiscoverableResponseSchema = z.object({
  ok: z.boolean(),
  discoverable: z.boolean(),
})

// ── WebSocket messages ──────────────────────────────────────

export const WsNewMessageSchema = z.object({
  type: z.literal('new_message'),
  messageId: UuidSchema,
  senderId: UuidSchema,
  senderUsername: UsernameSchema,
  encryptedPayload: z.string().min(1),
  timestamp: z.number(),
})

// Wire shapes below match what the server actually broadcasts
// (server/src/websocket/handler.ts handleTyping / handleReadReceipt), not the
// earlier placeholders that no code used. SEC-20260721-025.
export const WsReadReceiptSchema = z.object({
  type: z.literal('read'),
  senderId: UuidSchema,
  messageIds: z.array(UuidSchema).min(1).max(100),
  groupId: UuidSchema.optional(),
})

export const WsTypingSchema = z.object({
  type: z.literal('typing'),
  senderId: UuidSchema,
  senderUsername: UsernameSchema,
  isTyping: z.boolean(),
  groupId: UuidSchema.optional(),
})
