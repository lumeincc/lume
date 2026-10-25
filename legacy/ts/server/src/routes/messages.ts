// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { Router, Request, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'
import rateLimit from 'express-rate-limit'

import database from '../db/database'
import { broadcastToUser } from '../websocket/handler'
import { requireSignature } from '../middleware/auth'
import { validateBody, validateParams, validateQuery } from '../middleware/validate'
import {
  SendMessageBodySchema,
  PendingParamSchema,
  PendingQuerySchema,
  MessageIdParamSchema,
  AcknowledgeBodySchema,
} from '../schemas/messages'
import type { SendMessageBody } from '../schemas/messages'
import { parseEncryptedPayload } from '../schemas/common'
import { sendPushNotification } from '../services/pushService'

const router = Router()

const sendRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
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

const messagesReadRateLimit = rateLimit({
  windowMs: 60 * 1000,
  max: 240,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    if (req.user?.userId) return `msgread:${req.user.userId}`
    const identityKey = req.user?.identityKey
    if (identityKey) {
      const user = database.getUserByIdentityKey(identityKey)
      if (user) return `msgread:${user.id}`
    }
    return `msgread:ip:${req.ip || '127.0.0.1'}`
  },
})

// === Routes =================================================================

// POST /messages/send
router.post(
  '/send',
  requireSignature,
  sendRateLimit,
  validateBody(SendMessageBodySchema),
  (req: Request, res: Response) => {
    try {
      const { senderId, recipientId, encryptedPayload } = req.body as SendMessageBody

      if (!parseEncryptedPayload(encryptedPayload)) {
        res.status(400).json({ error: 'Invalid encrypted payload' })
        return
      }

      const sender = database.getUserById(senderId)
      if (!sender) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }

      if (sender.identity_key !== req.user?.identityKey) {
        res.status(403).json({ error: 'Identity mismatch' })
        return
      }

      // Look up by id (not username): the sender must already hold the recipient
      // id from a discoverable-respecting endpoint or invite. SEC-20260621-019.
      const recipient = database.getUserById(recipientId)
      if (!recipient) {
        res.status(404).json({ error: 'Recipient not found' })
        return
      }

      // If the recipient has blocked the sender, silently accept
      // (don't leak the block status to the sender)
      if (database.isBlocked(recipient.id, senderId)) {
        res.status(201).json({
          messageId: uuidv4(),
          delivered: false,
        })
        return
      }

      // Per-pair bound so one sender cannot consume the recipient's whole queue
      // and lock out every other sender. Sits below the global cap, which still
      // bounds total storage. SEC-20260721-011.
      const MAX_PENDING_PER_SENDER = 1000
      if (
        database.getPendingMessageCountFromSender(recipient.id, senderId) >= MAX_PENDING_PER_SENDER
      ) {
        res.status(429).json({ error: 'Too many pending messages to this recipient' })
        return
      }

      const MAX_PENDING_PER_USER = 10000
      if (database.getPendingMessageCount(recipient.id) >= MAX_PENDING_PER_USER) {
        res.status(429).json({ error: 'Recipient inbox is full' })
        return
      }

      const messageId = uuidv4()
      database.queueMessage(messageId, senderId, recipient.id, encryptedPayload)

      const delivered = broadcastToUser(recipient.id, {
        type: 'new_message',
        messageId,
        senderId,
        senderUsername: sender.username,
        encryptedPayload,
        timestamp: Date.now(),
      })

      // Send push notification if recipient is offline
      if (!delivered) {
        void sendPushNotification(recipient.id, sender.username)
      }

      res.status(201).json({
        messageId,
        delivered,
      })
    } catch (error) {
      console.error('Send message error:', error instanceof Error ? error.message : String(error))
      res.status(500).json({ error: 'Failed to send message' })
    }
  }
)

// GET /messages/pending/:userId
router.get(
  '/pending/:userId',
  requireSignature,
  messagesReadRateLimit,
  validateParams(PendingParamSchema),
  validateQuery(PendingQuerySchema),
  (req: Request, res: Response) => {
    try {
      const userId = req.params.userId!
      const { limit, after } = (
        req as Request & { validatedQuery?: { limit: number; after?: string } }
      ).validatedQuery ?? { limit: 100 }

      const user = database.getUserById(userId)
      if (!user || user.identity_key !== req.user?.identityKey) {
        res.status(403).json({ error: 'Unauthorized access to messages' })
        return
      }

      const { messages, hasMore } = database.getPendingMessages(userId, {
        limit,
        afterId: after,
      })
      const senderIds = [...new Set(messages.map(msg => msg.sender_id))]
      const senderMap = new Map(
        database.getUsersByIds(senderIds).map(sender => [sender.id, sender.username])
      )

      const messagesWithSenders = messages.map(msg => ({
        id: msg.id,
        senderId: msg.sender_id,
        senderUsername: senderMap.get(msg.sender_id) || 'unknown',
        encryptedPayload: msg.encrypted_payload,
        timestamp: msg.created_at * 1000,
      }))

      const lastMessage = messages[messages.length - 1]
      const nextCursor = hasMore && lastMessage ? lastMessage.id : null

      res.json({ messages: messagesWithSenders, nextCursor, hasMore })
    } catch (error) {
      console.error(
        'Get pending messages error:',
        error instanceof Error ? error.message : String(error)
      )
      res.status(500).json({ error: 'Failed to retrieve pending messages' })
    }
  }
)

// DELETE /messages/:messageId
router.delete(
  '/:messageId',
  requireSignature,
  messagesReadRateLimit,
  validateParams(MessageIdParamSchema),
  (req: Request, res: Response) => {
    try {
      const messageId = req.params.messageId!

      const signerId = req.user?.userId
      if (!signerId) {
        res.status(403).json({ error: 'Unauthorized' })
        return
      }

      const pending = database.getMessageById(messageId)
      if (!pending) {
        res.status(404).json({ error: 'Message not found' })
        return
      }

      if (pending.recipient_id !== signerId) {
        res.status(403).json({ error: 'Unauthorized access to message' })
        return
      }

      database.deleteMessage(messageId)
      res.json({ message: 'Message acknowledged' })
    } catch (error) {
      console.error(
        'Acknowledge message error:',
        error instanceof Error ? error.message : String(error)
      )
      res.status(500).json({ error: 'Failed to acknowledge message' })
    }
  }
)

// POST /messages/acknowledge
router.post(
  '/acknowledge',
  requireSignature,
  messagesReadRateLimit,
  validateBody(AcknowledgeBodySchema),
  (req: Request, res: Response) => {
    try {
      const { messageIds } = req.body as { messageIds: string[] }

      const signerId = req.user?.userId
      if (!signerId) {
        res.status(403).json({ error: 'Unauthorized' })
        return
      }

      let acknowledged = 0
      acknowledged = database.batchDeleteMessages(messageIds, signerId)

      res.json({ acknowledged })
    } catch (error) {
      console.error(
        'Batch acknowledge error:',
        error instanceof Error ? error.message : String(error)
      )
      res.status(500).json({ error: 'Failed to acknowledge messages' })
    }
  }
)

export default router
