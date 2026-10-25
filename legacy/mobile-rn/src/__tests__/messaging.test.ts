// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Guards around the message flow. The happy path is proven end-to-end against
 * the live relay by scripts/e2e-message.ts; what matters here are the failure
 * modes that must never regress — a relay substituting an identity, and a failed
 * first send leaving a session the recipient can never open.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'

const getBundle = vi.fn()
const send = vi.fn()

vi.mock('@/lib/api', () => ({
  authApi: { getBundle: (...a: unknown[]) => getBundle(...a) },
  messagesApi: { send: (...a: unknown[]) => send(...a) },
}))

import { sendMessage, receiveMessage } from '@/messaging'
import { generateIdentityKeys, generatePreKeyBundle, sign } from '@/crypto/keys'
import { vaultSetAuth, vaultClear, vaultGetSession } from '@/crypto/keyVault'
import { createNodeTestPlatform } from '@/platform/node'
import { setCurrentPlatform } from '@/platform/current'
import { savePreKeyMaterial } from '@/vault'
import { encodeBase64, decodeBase64 } from 'tweetnacl-util'

/** A well-formed bundle for a real identity, as the relay would return it. */
function bundleFor(identity: ReturnType<typeof generateIdentityKeys>) {
  const bundle = generatePreKeyBundle(identity.exchange, identity.signing, 2)
  return {
    id: 'peer-id',
    username: 'peer',
    identityKey: identity.signing.publicKey,
    exchangeIdentityKey: identity.exchange.publicKey,
    signedPrekey: bundle.signedPreKey.publicKey,
    signedPrekeySignature: bundle.signature,
    oneTimePrekey: bundle.oneTimePreKeys[0]!.publicKey,
  }
}

describe('messaging guards', () => {
  const me = generateIdentityKeys()
  const peer = generateIdentityKeys()
  let platform: ReturnType<typeof createNodeTestPlatform>

  beforeEach(async () => {
    vi.clearAllMocks()
    vaultClear()
    platform = createNodeTestPlatform()
    setCurrentPlatform(platform)
    vaultSetAuth(me, new Uint8Array(32).fill(1))
  })

  const target = { id: 'peer-id', username: 'peer' }

  it('rejects a bundle whose identity does not match the trusted contact (MITM)', async () => {
    const attacker = generateIdentityKeys()
    getBundle.mockResolvedValue({ data: bundleFor(attacker) })

    const res = await sendMessage('me-id', {
      ...target,
      // We already trust the real peer, so the attacker's bundle must be refused.
      trusted: { publicKey: peer.signing.publicKey, exchangeKey: peer.exchange.publicKey },
    }, 'hello')

    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error).toMatch(/does not match the trusted contact/)
    expect(send).not.toHaveBeenCalled()
  })

  it('rejects a bundle with a bad signed-prekey signature', async () => {
    const bundle = bundleFor(peer)
    // Same length, wrong signature.
    bundle.signedPrekeySignature = encodeBase64(new Uint8Array(64).fill(9))
    getBundle.mockResolvedValue({ data: bundle })

    const res = await sendMessage('me-id', target, 'hello')
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error).toMatch(/Invalid signed prekey signature/)
    expect(send).not.toHaveBeenCalled()
  })

  it('accepts a first contact when nothing is trusted yet (trust on first use)', async () => {
    getBundle.mockResolvedValue({ data: bundleFor(peer) })
    send.mockResolvedValue({ data: { messageId: 'm1' } })

    const res = await sendMessage('me-id', target, 'hello')
    expect(res.ok).toBe(true)
    expect(send).toHaveBeenCalledOnce()
  })

  it('does not persist a fresh X3DH session when the first send fails', async () => {
    getBundle.mockResolvedValue({ data: bundleFor(peer) })
    send.mockResolvedValue({ error: 'network down' })

    const res = await sendMessage('me-id', target, 'hello')
    expect(res.ok).toBe(false)
    // A retry must repeat the handshake; a stored session here would leave the
    // recipient permanently unable to derive the key.
    expect(vaultGetSession('peer-id')).toBeUndefined()
  })

  it('persists the session once the send succeeds', async () => {
    getBundle.mockResolvedValue({ data: bundleFor(peer) })
    send.mockResolvedValue({ data: { messageId: 'm1' } })

    await sendMessage('me-id', target, 'hello')
    expect(vaultGetSession('peer-id')).toBeDefined()
  })

  it('refuses an inbound X3DH header from an untrusted sender', async () => {
    const attacker = generateIdentityKeys()
    const envelope = JSON.stringify({
      v: 2,
      alg: 'lume-ratchet',
      header: { publicKey: encodeBase64(new Uint8Array(32)), previousChainLength: 0, messageNumber: 0 },
      ciphertext: 'AAAA',
      nonce: 'BBBB',
      timestamp: Date.now(),
      x3dh: {
        senderIdentityKey: attacker.exchange.publicKey,
        senderEphemeralKey: attacker.exchange.publicKey,
      },
    })

    const res = await receiveMessage(
      { id: 'm', senderId: 'peer-id', encryptedPayload: envelope },
      { exchangeKey: peer.exchange.publicKey }
    )
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error).toMatch(/does not match the trusted contact/)
  })

  it('refuses an inbound message with neither a session nor an X3DH header', async () => {
    const envelope = JSON.stringify({
      v: 2,
      alg: 'lume-ratchet',
      header: { publicKey: encodeBase64(new Uint8Array(32)), previousChainLength: 0, messageNumber: 0 },
      ciphertext: 'AAAA',
      nonce: 'BBBB',
      timestamp: Date.now(),
    })

    const res = await receiveMessage({ id: 'm', senderId: 'peer-id', encryptedPayload: envelope })
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error).toMatch(/no X3DH header/)
  })

  it('refuses an unreadable envelope', async () => {
    const res = await receiveMessage({ id: 'm', senderId: 'peer-id', encryptedPayload: 'not json' })
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error).toMatch(/Unreadable envelope/)
  })
})
