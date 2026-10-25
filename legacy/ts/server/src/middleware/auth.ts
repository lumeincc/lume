// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { Request, Response, NextFunction } from 'express'
import nacl from 'tweetnacl'
import { decodeBase64 } from 'tweetnacl-util'
import { createHash } from 'crypto'
import database from '../db/database'

function getCanonicalApiPath(req: Request): string {
  const url = req.originalUrl
  const [pathPart, queryPart] = url.split('?') as [string, string | undefined]
  const basePath = pathPart.startsWith('/api/')
    ? pathPart.slice('/api'.length)
    : pathPart === '/api'
      ? '/'
      : pathPart
  return queryPart ? `${basePath}?${queryPart}` : basePath
}

export const requireSignature = (req: Request, res: Response, next: NextFunction) => {
  try {
    const identityKey = Array.isArray(req.headers['x-lume-identity-key'])
      ? req.headers['x-lume-identity-key'][0]
      : (req.headers['x-lume-identity-key'] as string)
    const signature = Array.isArray(req.headers['x-lume-signature'])
      ? req.headers['x-lume-signature'][0]
      : (req.headers['x-lume-signature'] as string)
    const timestamp = Array.isArray(req.headers['x-lume-timestamp'])
      ? req.headers['x-lume-timestamp'][0]
      : (req.headers['x-lume-timestamp'] as string)
    const nonce = Array.isArray(req.headers['x-lume-nonce'])
      ? req.headers['x-lume-nonce'][0]
      : (req.headers['x-lume-nonce'] as string | undefined)
    const signedPath = Array.isArray(req.headers['x-lume-path'])
      ? req.headers['x-lume-path'][0]
      : (req.headers['x-lume-path'] as string | undefined)
    const requestMethod = req.method.toUpperCase()
    const requestPath = getCanonicalApiPath(req)

    if (!identityKey || !signature || !timestamp || !nonce || !signedPath) {
      res.status(401).json({ error: 'Missing authentication headers' })
      return
    }
    if (signedPath.length > 256 || !signedPath.startsWith('/')) {
      res.status(401).json({ error: 'Invalid signed path' })
      return
    }
    if (signedPath !== requestPath) {
      res.status(401).json({ error: 'Signed path mismatch' })
      return
    }

    let publicKeyBytes: Uint8Array
    let signatureBytes: Uint8Array
    try {
      publicKeyBytes = decodeBase64(identityKey)
      signatureBytes = decodeBase64(signature)
    } catch {
      res.status(401).json({ error: 'Invalid auth header format' })
      return
    }
    if (publicKeyBytes.length !== 32 || signatureBytes.length !== 64) {
      res.status(401).json({ error: 'Invalid auth header length' })
      return
    }

    // Prevent replay attacks (valid for 1 minute)
    const now = Date.now()
    let reqTime = parseInt(timestamp, 10)
    if (Number.isNaN(reqTime)) {
      res.status(401).json({ error: 'Invalid timestamp' })
      return
    }
    // Accept seconds or milliseconds
    if (reqTime < 1_000_000_000_000) {
      reqTime *= 1000
    }
    if (Math.abs(now - reqTime) > 60000) {
      res.status(401).json({ error: 'Request expired' })
      return
    }

    // Verify user exists and key matches
    // Ideally we check if the identityKey belongs to the claimed userId in the body/params
    // But the middleware is generic. Let's verify the signature first.

    // Message = timestamp + nonce + method + api path + raw JSON body.
    // Accept both "" and "{}" for empty bodies to be tolerant of empty payload clients.
    const rawBody = (req as Request & { rawBody?: string }).rawBody
    const bodyCandidates: string[] = []

    if (rawBody !== undefined && rawBody.length > 0) {
      bodyCandidates.push(rawBody)
    } else if (req.body && Object.keys(req.body).length > 0) {
      bodyCandidates.push(JSON.stringify(req.body))
    } else {
      bodyCandidates.push('')
    }

    const isValid = bodyCandidates.some(body => {
      const message = `${timestamp}.${nonce}.${requestMethod}.${signedPath}.${body}`
      const messageBytes = new TextEncoder().encode(message)
      return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes)
    })

    if (!isValid) {
      res.status(403).json({ error: 'Invalid signature' })
      return
    }

    const replayHash = createHash('sha256')
      .update(identityKey)
      .update('|')
      .update(timestamp)
      .update('|')
      .update(signature)
      .update('|')
      .update(nonce)
      .update('|')
      .update(requestMethod)
      .update('|')
      .update(signedPath)
      .digest('hex')

    if (!database.rememberRequestSignature(replayHash, identityKey)) {
      res.status(409).json({ error: 'Duplicate request' })
      return
    }

    // Pass identity key (and resolved userId when available) to next handler
    const signer = database.getUserByIdentityKey(identityKey)
    req.user = { identityKey, userId: signer?.id }
    next()
  } catch (error) {
    console.error('Auth middleware error:', error instanceof Error ? error.message : String(error))
    res.status(500).json({ error: 'Internal auth error' })
  }
}

// Extend Express Request type
declare global {
  namespace Express {
    interface Request {
      user?: {
        identityKey: string
        userId?: string
      }
    }
  }
}
