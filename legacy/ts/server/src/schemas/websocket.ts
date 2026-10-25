// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { z } from 'zod'

const PingMessageSchema = z.object({
  type: z.literal('ping'),
})

const TypingMessageSchema = z.object({
  type: z.literal('typing'),
  recipientId: z.string(),
  isTyping: z.boolean(),
  // Present when the typing event belongs to a group fan-out. The server only
  // relays it so the recipient can attribute typing to the group rather than a
  // 1:1 chat; the server never learns group membership.
  groupId: z.string().uuid().optional(),
})

/**
 * Ceiling on a single receipt. SEC-20260721-005.
 *
 * The handler already refused more than 100 ids, but only after Zod had parsed
 * the whole array — an arbitrarily long one was allocated and walked before
 * anything rejected it. Enforcing it in the schema moves the bound ahead of the
 * allocation, which is the point of validating at the boundary.
 */
const MAX_READ_RECEIPT_IDS = 100

const ReadReceiptMessageSchema = z.object({
  type: z.literal('read'),
  recipientId: z.string(),
  messageIds: z.array(z.string()).max(MAX_READ_RECEIPT_IDS),
  // Present when acknowledging messages read inside a group (relayed only).
  groupId: z.string().uuid().optional(),
})

export const WsMessageSchema = z.discriminatedUnion('type', [
  PingMessageSchema,
  TypingMessageSchema,
  ReadReceiptMessageSchema,
])

export type WsMessage = z.infer<typeof WsMessageSchema>
export type TypingMessage = z.infer<typeof TypingMessageSchema>
export type ReadReceiptMessage = z.infer<typeof ReadReceiptMessageSchema>
