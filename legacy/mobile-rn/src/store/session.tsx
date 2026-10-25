// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * App state: the open session, contacts, messages, and the live connection.
 *
 * Deliberately a small React context rather than another state library. The
 * engine already owns everything hard — keys, the ratchet, persistence, delivery
 * — so this layer only mirrors it for rendering and routes user actions back
 * into it.
 *
 * Plaintext messages live here in memory and are written to the encrypted vault;
 * nothing readable is kept anywhere else.
 *
 * Three things here exist because a phone is not a desktop:
 *
 *   - sending goes through the outbox, so a message survives a dead connection
 *     and an app restart instead of vanishing with an error toast;
 *   - vault writes are collapsed (lib/writeBehind.ts), because a reconnect drains
 *     a burst of messages and each one used to re-encrypt the whole history;
 *   - the app being backgrounded and foregrounded is handled explicitly, since
 *     that is the normal way a phone loses and regains its socket.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { AppState, type AppStateStatus } from 'react-native'
import { devicePlatform } from '../platform/reactNativeFull'
import { openSession, closeSession, flushSessions } from '../session'
import { registerNewAccount, restoreAccountFromMnemonic, rebindIdentity } from '../registration'
import { hasAccount, loadMessages, saveMessages, saveContacts, MAX_STORED_MESSAGES } from '../vault'
import { sendMessage as engineSend, receiveMessage as engineReceive } from '../messaging'
import { Outbox, type OutboxEntry } from '../outbox'
import { createWriteBehind, type WriteBehind } from '../lib/writeBehind'
import { RealtimeClient, type ConnectionStatus } from '../realtime'
import { authApi, messagesApi } from '../lib/api'
import { vaultGetMasterKey } from '../crypto/keyVault'
import type { AccountProfile, Contact, StoredMessage } from '../vault'
import type { IdentityKeys } from '../crypto/keys'

interface SessionState {
  ready: boolean
  accountExists: boolean
  unlocked: boolean
  profile: AccountProfile | null
  contacts: Contact[]
  messages: StoredMessage[]
  connection: ConnectionStatus
  /** Why the socket dropped, when it did — a bare "offline" hides real faults. */
  connectionDetail: string | null
  error: string | null
}

interface SessionActions {
  /** Returns the recovery phrase, which exists only at this moment. */
  register(username: string, pin: string): Promise<{ ok: true; mnemonic: string } | { ok: false; error: string }>
  restore(mnemonic: string, username: string, pin: string): Promise<string | null>
  unlock(pin: string): Promise<string | null>
  lock(): Promise<void>
  addContact(username: string): Promise<string | null>
  /**
   * Hand a message to the outbox. Resolves as soon as it is durably queued, not
   * when it is delivered — the conversation shows it immediately and its status
   * updates as delivery progresses.
   */
  send(contactId: string, text: string): Promise<string | null>
  /** Re-queue a message the user had given up on. */
  retry(messageId: string): void
  messagesWith(contactId: string): StoredMessage[]
  dismissError(): void
}

const Ctx = createContext<(SessionState & SessionActions) | null>(null)

export function useSession() {
  const value = useContext(Ctx)
  if (!value) throw new Error('useSession must be used inside <SessionProvider>')
  return value
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionState>({
    ready: false,
    accountExists: false,
    unlocked: false,
    profile: null,
    contacts: [],
    messages: [],
    connection: 'idle',
    connectionDetail: null,
    error: null,
  })

  const realtime = useRef<RealtimeClient | null>(null)
  const outbox = useRef<Outbox | null>(null)
  const profileRef = useRef<AccountProfile | null>(null)
  const identityRef = useRef<IdentityKeys | null>(null)
  const messagesRef = useRef<StoredMessage[]>([])
  const contactsRef = useRef<Contact[]>([])

  /**
   * Ids already accepted, claimed before the first await.
   *
   * Checking the message list instead left a window: the socket can deliver a
   * frame while the same message is still being decrypted from the pending
   * drain, and both passed the check. Sender-side `clientId`s live here too, so a
   * message re-sent after an ambiguous timeout is recognised as the repeat it is.
   */
  const seenRef = useRef<Set<string>>(new Set())

  const messageWriter = useRef<WriteBehind<StoredMessage[]> | null>(null)
  const contactWriter = useRef<WriteBehind<Contact[]> | null>(null)

  useEffect(() => {
    void hasAccount(devicePlatform)
      .then(exists => setState(s => ({ ...s, ready: true, accountExists: exists })))
      .catch(e => setState(s => ({ ...s, ready: true, error: describe(e) })))
  }, [])

  const persistMessages = useCallback((next: StoredMessage[]) => {
    // The cap is applied here as well as in the vault, so the in-memory list a
    // long-lived session holds stays bounded too.
    const capped = next.length > MAX_STORED_MESSAGES ? next.slice(-MAX_STORED_MESSAGES) : next
    messagesRef.current = capped
    setState(s => ({ ...s, messages: capped }))
    messageWriter.current?.queue(capped)
  }, [])

  const persistContacts = useCallback((next: Contact[]) => {
    contactsRef.current = next
    setState(s => ({ ...s, contacts: next }))
    contactWriter.current?.queue(next)
  }, [])

  /** Replace one message in place, keeping order. */
  const patchMessage = useCallback(
    (id: string, patch: Partial<StoredMessage>) => {
      const index = messagesRef.current.findIndex(m => m.id === id)
      if (index === -1) return
      const next = [...messagesRef.current]
      next[index] = { ...next[index]!, ...patch }
      persistMessages(next)
    },
    [persistMessages]
  )

  /** Decrypt an inbound message and file it under the right contact. */
  const ingest = useCallback(
    async (incoming: { id: string; senderId: string; senderUsername?: string; encryptedPayload: string }) => {
      if (seenRef.current.has(incoming.id)) return
      seenRef.current.add(incoming.id)

      const known = contactsRef.current.find(c => c.id === incoming.senderId)
      const res = await engineReceive(
        { id: incoming.id, senderId: incoming.senderId, encryptedPayload: incoming.encryptedPayload },
        known ? { publicKey: known.publicKey, exchangeKey: known.exchangeKey } : null
      )
      if (!res.ok) {
        // Release the claim: a failure that was transient (a prekey the sender
        // will resend, a moment of storage trouble) must not make the message
        // permanently unprocessable if the relay offers it again.
        seenRef.current.delete(incoming.id)
        setState(s => ({ ...s, error: res.error }))
        return
      }

      // The sender's own id survives their retries, so this is what catches a
      // message the relay stored twice after a timed-out send.
      if (res.clientId) {
        if (seenRef.current.has(res.clientId)) return
        seenRef.current.add(res.clientId)
      }

      // Two entries per message would otherwise grow without limit in a session
      // that stays open for days. Rebuilding from the stored list keeps dedup
      // working where it matters — duplicates arrive within seconds, not weeks.
      if (seenRef.current.size > SEEN_LIMIT) {
        seenRef.current = new Set(messagesRef.current.map(m => m.id))
      }

      // First contact: remember who they are, so later handshakes are pinned.
      if (!known && incoming.senderUsername) {
        const bundle = await authApi.getBundle(incoming.senderUsername)
        if (bundle.data) {
          persistContacts([
            ...contactsRef.current,
            {
              id: incoming.senderId,
              username: incoming.senderUsername,
              publicKey: bundle.data.identityKey,
              exchangeKey: bundle.data.exchangeIdentityKey || bundle.data.exchangeKey || '',
              addedAt: Date.now(),
            },
          ])
        }
      }

      persistMessages([
        ...messagesRef.current,
        {
          id: incoming.id,
          contactId: incoming.senderId,
          outgoing: false,
          text: res.text,
          timestamp: res.timestamp,
        },
      ])
    },
    [persistContacts, persistMessages]
  )

  /** Ask the relay for anything queued while this device was away. */
  const drainPending = useCallback(
    async (userId: string) => {
      try {
        const res = await messagesApi.getPending(userId)
        if (res.error || !res.data) return
        for (const m of res.data.messages) {
          await ingest({
            id: m.id,
            senderId: m.senderId,
            senderUsername: m.senderUsername,
            encryptedPayload: m.encryptedPayload,
          })
        }
      } catch (e) {
        setState(s => ({ ...s, error: `Не удалось забрать сообщения: ${describe(e)}` }))
      }
    },
    [ingest]
  )

  /** Pull anything queued while the app was closed, then stay connected. */
  const startRealtime = useCallback(
    async (initialUserId: string) => {
      let userId = initialUserId
      await drainPending(userId)

      let token = await authApi.getSession(userId)

      // "User not found" means the relay lost its row, not that anything is wrong
      // with this account — the identity here is authoritative. Republish it and
      // carry on; the identity and safety numbers are unchanged.
      if (token.error && /not found/i.test(token.error) && identityRef.current && profileRef.current) {
        const rebind = await rebindIdentity(
          devicePlatform,
          identityRef.current,
          profileRef.current.username,
          vaultGetMasterKey()
        )
        if (rebind.ok) {
          profileRef.current = { userId: rebind.userId, username: profileRef.current.username }
          setState(s => ({ ...s, profile: profileRef.current }))
          userId = rebind.userId
          token = await authApi.getSession(userId)
        }
      }

      if (token.error || !token.data) {
        setState(s => ({
          ...s,
          connection: 'auth_error',
          connectionDetail: token.error ?? 'сервер не выдал токен',
        }))
        return
      }

      realtime.current?.disconnect()
      realtime.current = new RealtimeClient({
        onStatus: (connection, detail) => {
          setState(s => ({
            ...s,
            connection,
            connectionDetail: detail?.code
              ? `${detail.code}${detail.reason ? `: ${detail.reason}` : ''}`
              : null,
          }))
          // A live socket is the clearest proof the network is back, so it is
          // what releases anything waiting out a backoff.
          if (connection === 'connected') outbox.current?.kick()
        },
        onMessage: m => void ingest(m),
        onTokenRefreshNeeded: async () => {
          const fresh = await authApi.getSession(userId)
          return fresh.data?.token ?? null
        },
      })
      realtime.current.connect(token.data.token)
    },
    [drainPending, ingest]
  )

  /** Deliver one queued message; the outbox owns retries and ordering. */
  const deliver = useCallback(async (entry: OutboxEntry) => {
    const profile = profileRef.current
    const contact = contactsRef.current.find(c => c.id === entry.contactId)
    if (!profile || !contact) {
      return { ok: false as const, error: 'Контакт не найден', retryable: false }
    }
    return engineSend(
      profile.userId,
      {
        id: contact.id,
        username: contact.username,
        trusted: { publicKey: contact.publicKey, exchangeKey: contact.exchangeKey },
        exchangeKey: contact.exchangeKey || undefined,
      },
      entry.text,
      entry.id
    )
  }, [])

  const afterOpen = useCallback(
    async (profile: AccountProfile | null, contacts: Contact[], identity: IdentityKeys) => {
      profileRef.current = profile
      identityRef.current = identity
      contactsRef.current = contacts

      // Writers are bound to this session's master key by way of the key vault,
      // so they are built per unlock and torn down with it.
      messageWriter.current = createWriteBehind<StoredMessage[]>(next =>
        saveMessages(devicePlatform, next, vaultGetMasterKey())
      )
      contactWriter.current = createWriteBehind<Contact[]>(next =>
        saveContacts(devicePlatform, next, vaultGetMasterKey())
      )

      const stored = await loadMessages(devicePlatform, vaultGetMasterKey())
      messagesRef.current = stored
      seenRef.current = new Set(stored.map(m => m.id))
      setState(s => ({
        ...s,
        unlocked: true,
        accountExists: true,
        profile,
        contacts,
        messages: stored,
        error: null,
      }))

      outbox.current?.stop()
      outbox.current = new Outbox({
        deliver,
        onOutcome: (entry, outcome) =>
          patchMessage(entry.id, {
            status: outcome.status,
            error: outcome.error,
            ...(outcome.serverId ? { serverId: outcome.serverId } : {}),
          }),
      })
      // Anything still pending from the last run is the user's message that was
      // never delivered — it goes back on the queue before anything new.
      outbox.current.restore(
        stored
          .filter(m => m.outgoing && m.status === 'pending')
          .map(m => ({ id: m.id, contactId: m.contactId, text: m.text, createdAt: m.timestamp, attempts: 0 }))
      )

      if (profile) void startRealtime(profile.userId)
    },
    [deliver, patchMessage, startRealtime]
  )

  const register = useCallback(
    async (
      username: string,
      pin: string
    ): Promise<{ ok: true; mnemonic: string } | { ok: false; error: string }> => {
      const res = await registerNewAccount(devicePlatform, username.trim(), pin)
      if (!res.ok) return { ok: false, error: res.error }
      const opened = await openSession(devicePlatform, pin)
      if (!opened.ok) return { ok: false, error: opened.reason }
      await afterOpen(opened.profile, opened.contacts, opened.identity)
      return { ok: true, mnemonic: res.account.mnemonic }
    },
    [afterOpen]
  )

  const restore = useCallback(
    async (mnemonic: string, username: string, pin: string) => {
      const res = await restoreAccountFromMnemonic(devicePlatform, mnemonic.trim(), username.trim(), pin)
      if (!res.ok) return res.error
      const opened = await openSession(devicePlatform, pin)
      if (!opened.ok) return opened.reason
      await afterOpen(opened.profile, opened.contacts, opened.identity)
      return null
    },
    [afterOpen]
  )

  const unlock = useCallback(
    async (pin: string) => {
      const opened = await openSession(devicePlatform, pin)
      if (!opened.ok) {
        return opened.reason === 'wrong-pin' ? 'Неверный PIN' : opened.reason
      }
      await afterOpen(opened.profile, opened.contacts, opened.identity)
      return null
    },
    [afterOpen]
  )

  const lock = useCallback(async () => {
    realtime.current?.disconnect()
    realtime.current = null
    outbox.current?.stop()
    outbox.current = null

    // Everything that still needs the master key must land before it is zeroed.
    await messageWriter.current?.flush()
    await contactWriter.current?.flush()
    await flushSessions()
    await closeSession()

    messageWriter.current = null
    contactWriter.current = null
    messagesRef.current = []
    contactsRef.current = []
    seenRef.current = new Set()
    setState(s => ({ ...s, unlocked: false, profile: null, contacts: [], messages: [], connection: 'idle' }))
  }, [])

  const addContact = useCallback(
    async (username: string) => {
      const name = username.trim()
      if (!name) return 'Введите имя пользователя'
      if (contactsRef.current.some(c => c.username === name)) return 'Контакт уже добавлен'

      const bundle = await authApi.getBundle(name)
      if (bundle.error || !bundle.data) return bundle.error ?? 'Пользователь не найден'

      persistContacts([
        ...contactsRef.current,
        {
          id: bundle.data.id,
          username: bundle.data.username,
          publicKey: bundle.data.identityKey,
          exchangeKey: bundle.data.exchangeIdentityKey || bundle.data.exchangeKey || '',
          addedAt: Date.now(),
        },
      ])
      return null
    },
    [persistContacts]
  )

  const send = useCallback(
    async (contactId: string, text: string) => {
      const profile = profileRef.current
      const contact = contactsRef.current.find(c => c.id === contactId)
      if (!profile || !contact) return 'Контакт не найден'
      if (!outbox.current) return 'Сессия закрыта'

      const id = newMessageId()
      const entry: OutboxEntry = { id, contactId, text, createdAt: Date.now(), attempts: 0 }

      // Written first, queued second: if the app dies between the two the message
      // is recovered as pending at the next unlock. The other order would lose it.
      persistMessages([
        ...messagesRef.current,
        { id, contactId, outgoing: true, text, timestamp: entry.createdAt, status: 'pending' },
      ])
      await messageWriter.current?.flush()
      outbox.current.enqueue(entry)
      return null
    },
    [persistMessages]
  )

  const retry = useCallback(
    (messageId: string) => {
      const message = messagesRef.current.find(m => m.id === messageId)
      if (!message || !outbox.current) return
      patchMessage(messageId, { status: 'pending', error: undefined })
      outbox.current.retry({
        id: message.id,
        contactId: message.contactId,
        text: message.text,
        createdAt: message.timestamp,
        attempts: 0,
      })
    },
    [patchMessage]
  )

  /**
   * Group messages by contact once per change instead of filtering and sorting
   * the whole history on every render of every screen.
   */
  const byContact = useMemo(() => {
    const index = new Map<string, StoredMessage[]>()
    for (const message of state.messages) {
      const bucket = index.get(message.contactId)
      if (bucket) bucket.push(message)
      else index.set(message.contactId, [message])
    }
    for (const bucket of index.values()) bucket.sort((a, b) => a.timestamp - b.timestamp)
    return index
  }, [state.messages])

  const messagesWith = useCallback((contactId: string) => byContact.get(contactId) ?? EMPTY, [byContact])

  const dismissError = useCallback(() => setState(s => ({ ...s, error: null })), [])

  /**
   * Follow the app in and out of the background.
   *
   * Backgrounding is when the OS is most likely to freeze or kill the process, so
   * pending writes are flushed then — losing the ratchet state there breaks the
   * conversation permanently for both sides. Coming back is the moment the socket
   * has almost certainly died silently, so the connection is resumed, the relay
   * is asked for what it held, and the outbox is released from any backoff.
   */
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (next: AppStateStatus) => {
      if (!profileRef.current) return
      if (next === 'background' || next === 'inactive') {
        void flushSessions()
        void messageWriter.current?.flush()
        void contactWriter.current?.flush()
        return
      }
      if (next === 'active') {
        realtime.current?.resume()
        outbox.current?.kick()
        void drainPending(profileRef.current.userId)
      }
    })
    return () => subscription.remove()
  }, [drainPending])

  const value = useMemo(
    () => ({ ...state, register, restore, unlock, lock, addContact, send, retry, messagesWith, dismissError }),
    [state, register, restore, unlock, lock, addContact, send, retry, messagesWith, dismissError]
  )

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

const EMPTY: StoredMessage[] = []

/** Ceiling for the dedup set; see where it is enforced in `ingest`. */
const SEEN_LIMIT = MAX_STORED_MESSAGES * 4

function describe(e: unknown) {
  return e instanceof Error ? e.message : String(e)
}

/**
 * A local id for a message that does not have a server one yet.
 *
 * Random rather than sequential: it travels inside the sealed payload as the
 * dedup token, and a counter would tell the recipient how many messages this
 * device has ever sent.
 */
function newMessageId(): string {
  const bytes = devicePlatform.crypto.randomBytes(16)
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return `local-${out}`
}
