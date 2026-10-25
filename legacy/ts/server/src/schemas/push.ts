// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Zod schemas for /push routes.
 */

import { z } from 'zod'
import { UuidSchema } from './common'
import { isSafePushEndpoint, MAX_PUSH_ENDPOINT_LEN, MAX_PUSH_KEY_LEN } from '../utils/pushEndpoint'

const PushSubscriptionSchema = z.object({
  endpoint: z
    .string()
    .max(MAX_PUSH_ENDPOINT_LEN)
    .refine(isSafePushEndpoint, 'Unsafe or invalid push endpoint'),
  keys: z.object({
    p256dh: z.string().min(1, 'p256dh key required').max(MAX_PUSH_KEY_LEN),
    auth: z.string().min(1, 'auth key required').max(MAX_PUSH_KEY_LEN),
  }),
})

// POST /push/subscribe
export const SubscribeBodySchema = z.object({
  userId: UuidSchema,
  subscription: PushSubscriptionSchema,
})

// POST /push/unsubscribe
export const UnsubscribeBodySchema = z.object({
  userId: UuidSchema,
})
