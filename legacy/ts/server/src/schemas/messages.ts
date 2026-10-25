// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Zod schemas for /messages routes.
 */

import { z } from 'zod'
import { UuidSchema, UuidArraySchema } from './common'

/** Encrypted payload: JSON string, max 64KB */
export const EncryptedPayloadStringSchema = z
  .string()
  .min(1, 'Payload must not be empty')
  .max(65536, 'Payload exceeds 64KB limit')

// POST /messages/send
export const SendMessageBodySchema = z.object({
  senderId: UuidSchema,
  // Send by recipient id (UUID), not username — eliminates username enumeration /
  // probing of non-discoverable users via /messages/send. SEC-20260621-019.
  recipientId: UuidSchema,
  encryptedPayload: EncryptedPayloadStringSchema,
})
export type SendMessageBody = z.infer<typeof SendMessageBodySchema>

// GET /messages/pending/:userId
export const PendingParamSchema = z.object({
  userId: UuidSchema,
})

// GET /messages/pending/:userId query params (cursor-based pagination)
export const PendingQuerySchema = z.object({
  limit: z
    .string()
    .optional()
    .transform(val => (val !== undefined ? Number(val) : 100))
    .pipe(z.number().int().min(1).max(200)),
  after: UuidSchema.optional(),
})

// DELETE /messages/:messageId
export const MessageIdParamSchema = z.object({
  messageId: UuidSchema,
})

// POST /messages/acknowledge
export const AcknowledgeBodySchema = z.object({
  messageIds: UuidArraySchema,
})
