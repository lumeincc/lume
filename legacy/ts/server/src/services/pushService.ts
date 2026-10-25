// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Web Push notification service.
 * Uses VAPID for authentication. Subscriptions are stored as JSON in the push_token column.
 */

import webpush from 'web-push'
import database from '../db/database'

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || ''
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || ''
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:admin@lume.local'

let initialized = false

function ensureInitialized(): boolean {
  if (initialized) return true
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return false
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY)
  initialized = true
  return true
}

export function getVapidPublicKey(): string {
  return VAPID_PUBLIC_KEY
}

export function isWebPushEnabled(): boolean {
  return !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY)
}

/**
 * Send a push notification to a user (if they have a subscription).
 * Never includes message content or sender identity — generic notification only.
 */
export async function sendPushNotification(
  recipientId: string,
  _senderUsername: string
): Promise<boolean> {
  if (!ensureInitialized()) return false

  const user = database.getUserById(recipientId)
  if (!user?.push_token) return false

  let subscription: webpush.PushSubscription
  try {
    subscription = JSON.parse(user.push_token) as webpush.PushSubscription
  } catch {
    return false
  }

  const payload = JSON.stringify({
    title: 'LUME',
    body: 'You have a new message',
    tag: 'lume-new-message',
  })

  try {
    await webpush.sendNotification(subscription, payload)
    return true
  } catch (err) {
    const statusCode = (err as { statusCode?: number }).statusCode
    // 404 or 410 means subscription is no longer valid — clean up
    if (statusCode === 404 || statusCode === 410) {
      database.setPushToken(recipientId, '')
    }
    return false
  }
}
