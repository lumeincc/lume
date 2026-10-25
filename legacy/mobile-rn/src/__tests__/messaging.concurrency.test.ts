// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * The ratchet is a read-advance-write state machine, and on a phone its two entry
 * points genuinely overlap: the socket delivers a frame while the pending-message
 * drain is still running, or the user taps send twice.
 *
 * Both failures below were reachable before lib/serialQueue.ts existed, and
 * neither announces itself — a message is simply never seen again.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'

const getBundle = vi.fn()
const send = vi.fn()

vi.mock('@/lib/api', () => ({
  authApi: { getBundle: (...a: unknown[]) => getBundle(...a) },
  messagesApi: { send: (...a: unknown[]) => send(...a) },
}))

import { sendMessage, receiveMessage } from '@/messaging'
import { generateIdentityKeys, generatePreKeyBundle } from '@/crypto/keys'
import { x3dhInitiate, initSenderSession, ratchetEncrypt } from '@/crypto/ratchet'
import { vaultSetAuth, vaultClear, vaultGetSession } from '@/crypto/keyVault'
import { createNodeTestPlatform } from '@/platform/node'
import { setCurrentPlatform } from '@/platform/current'
import { savePreKeyMaterial } from '@/vault'
import { encodeRatchetEnvelope, parseRatchetEnvelope } from '@/lib/ratchetPayload'
import { encodeWirePayload } from '@/lib/wirePayload'

const MASTER_KEY = new Uint8Array(32).fill(7)

describe('concurrent ratchet operations', () => {
  const me = generateIdentityKeys()
  const peer = generateIdentityKeys()
  let platform: ReturnType<typeof createNodeTestPlatform>

  beforeEach(() => {
    vi.clearAllMocks()
    vaultClear()
    platform = createNodeTestPlatform()
    setCurrentPlatform(platform)
    vaultSetAuth(me, MASTER_KEY)
  })

  const target = { id: 'peer-id', username: 'peer' }

  function peerBundle() {
    const bundle = generatePreKeyBundle(peer.exchange, peer.signing, 2)
    return {
      id: 'peer-id',
      username: 'peer',
      identityKey: peer.signing.publicKey,
      exchangeIdentityKey: peer.exchange.publicKey,
      signedPrekey: bundle.signedPreKey.publicKey,
      signedPrekeySignature: bundle.signature,
      oneTimePrekey: bundle.oneTimePreKeys[0]!.publicKey,
    }
  }

  it('gives two simultaneous sends different message numbers', async () => {
    getBundle.mockResolvedValue({ data: peerBundle() })
    send.mockResolvedValue({ data: { messageId: 'm0' } })

    // Establish the session first, so both concurrent sends take the common path
    // of encrypting from an existing sending chain.
    await sendMessage('me-id', target, 'first')
    expect(vaultGetSession('peer-id')).toBeDefined()

    // Overlap the two sends: each holds the relay for a tick, which is exactly
    // the window in which the second used to read the same chain state.
    const payloads: string[] = []
    send.mockImplementation(async (body: { encryptedPayload: string }) => {
      payloads.push(body.encryptedPayload)
      await new Promise(resolve => setTimeout(resolve, 10))
      return { data: { messageId: `m${payloads.length}` } }
    })

    const [a, b] = await Promise.all([
      sendMessage('me-id', target, 'hello'),
      sendMessage('me-id', target, 'world'),
    ])

    expect(a.ok).toBe(true)
    expect(b.ok).toBe(true)
    expect(payloads).toHaveLength(2)

    const numbers = payloads.map(p => parseRatchetEnvelope(p)!.header.messageNumber)
    // Two messages sharing a number share a message key, and the recipient can
    // only ever open one of them — the other is lost with no error anywhere.
    expect(new Set(numbers).size).toBe(2)
  })

  it('lets a follow-up message decrypt when it arrives with the handshake', async () => {
    // Give this device prekey material, so it can answer an X3DH handshake.
    const mine = generatePreKeyBundle(me.exchange, me.signing, 2)
    await savePreKeyMaterial(
      platform,
      {
        signedPreKey: mine.signedPreKey,
        oneTimePreKeys: mine.oneTimePreKeys,
        updatedAt: Date.now(),
        spkCreatedAt: Date.now(),
      },
      MASTER_KEY
    )

    // The peer opens a session against our bundle and sends two messages. Only
    // the first carries the X3DH header — which is what the real send path does.
    const { sharedSecret, ephemeralPublicKey } = x3dhInitiate(peer.exchange, {
      identityKey: me.exchange.publicKey,
      signingKey: me.signing.publicKey,
      signedPreKey: mine.signedPreKey.publicKey,
      signature: mine.signature,
      oneTimePreKey: mine.oneTimePreKeys[0]!.publicKey,
    })
    const peerSession = initSenderSession(sharedSecret, mine.signedPreKey.publicKey)

    const envelopes = ['one', 'two'].map((text, index) => {
      const encrypted = ratchetEncrypt(
        peerSession,
        new TextEncoder().encode(encodeWirePayload(text, Date.now()))
      )
      return encodeRatchetEnvelope({
        encrypted,
        timestamp: Date.now(),
        ...(index === 0
          ? {
              x3dh: {
                senderIdentityKey: peer.exchange.publicKey,
                senderEphemeralKey: ephemeralPublicKey,
                recipientOneTimePreKey: mine.oneTimePreKeys[0]!.publicKey,
                recipientSignedPreKey: mine.signedPreKey.publicKey,
              },
            }
          : {}),
      })
    })

    // Deliver both at once — the socket and the pending drain really do race.
    const trusted = { publicKey: peer.signing.publicKey, exchangeKey: peer.exchange.publicKey }
    const [first, second] = await Promise.all([
      receiveMessage({ id: 'm1', senderId: 'peer-id', encryptedPayload: envelopes[0]! }, trusted),
      receiveMessage({ id: 'm2', senderId: 'peer-id', encryptedPayload: envelopes[1]! }, trusted),
    ])

    // Without serialisation the second call reads the vault before the first has
    // committed the new session, finds nothing, and rejects a perfectly good
    // message as having "no session and no X3DH header".
    expect(first.ok).toBe(true)
    expect(second.ok).toBe(true)
    if (first.ok && second.ok) {
      expect([first.text, second.text].sort()).toEqual(['one', 'two'])
    }
  })

  it('keeps different contacts independent', async () => {
    getBundle.mockResolvedValue({ data: peerBundle() })
    let inFlight = 0
    let sawOverlap = false
    send.mockImplementation(async () => {
      inFlight++
      if (inFlight > 1) sawOverlap = true
      await new Promise(resolve => setTimeout(resolve, 10))
      inFlight--
      return { data: { messageId: 'm' } }
    })

    await Promise.all([
      sendMessage('me-id', { id: 'peer-a', username: 'a' }, 'hi'),
      sendMessage('me-id', { id: 'peer-b', username: 'b' }, 'hi'),
    ])

    // Serialising by contact must not turn the whole app into one queue.
    expect(sawOverlap).toBe(true)
  })
})
