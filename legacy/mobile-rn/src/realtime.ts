// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Real-time delivery over WebSocket.
 *
 * This is a port rather than a verbatim vendor: the web client's lib/websocket.ts
 * writes connection state straight into Zustand UI stores, which would drag the
 * interface layer into the engine. The wire protocol, close-code handling, ping
 * cadence and backoff are kept identical — only the reporting is inverted, so
 * this module emits events and the UI subscribes.
 *
 * Every inbound frame is validated with the same Zod schemas the web uses. The
 * relay is untrusted by design, so nothing here acts on an unvalidated frame.
 */

import { WsNewMessageSchema, WsTypingSchema, WsReadReceiptSchema } from './lib/schemas'
import { WS_URL, APP_ORIGIN } from './lib/config'

/**
 * The subset of the WebSocket API this client uses. Declared explicitly because
 * the socket is injectable: React Native's WebSocket takes a third `options`
 * argument the DOM type does not know about, and Node's built-in WebSocket
 * cannot send custom headers at all, so tests supply the `ws` package instead.
 */
export interface WebSocketLike {
  readyState: number
  send(data: string): void
  close(): void
  onopen: ((ev: unknown) => void) | null
  onmessage: ((ev: { data: unknown }) => void) | null
  onclose: ((ev: { code: number; reason: string }) => void) | null
  onerror: ((ev: unknown) => void) | null
}

export type SocketFactory = (
  url: string,
  protocols: string[],
  options: { headers: Record<string, string> }
) => WebSocketLike

/**
 * Default factory.
 *
 * The Origin header is the load-bearing part: the relay rejects a handshake
 * whose Origin is not allow-listed, and an empty one never is. It then closes
 * with 4007 and immediately terminates, so the close frame is lost and the
 * client only ever sees a bare 1006 — which is exactly how this presented.
 * Browsers set Origin themselves and ignore the extra argument; React Native
 * sends none unless asked, which is why it is passed here.
 */
const defaultSocketFactory: SocketFactory = (url, protocols, options) =>
  new (WebSocket as unknown as {
    new (u: string, p: string[], o: { headers: Record<string, string> }): WebSocketLike
  })(url, protocols, options)

/** Close codes the relay uses to explain an auth failure. */
const CloseCodes = {
  MISSING_AUTH: 4001,
  INVALID_AUTH: 4002,
  EXPIRED_AUTH: 4003,
  TOO_MANY_CONNECTIONS: 4005,
  RATE_LIMITED: 4006,
} as const

const PING_INTERVAL_MS = 30_000
const BASE_RECONNECT_DELAY_MS = 1_000
const MAX_RECONNECT_DELAY_MS = 30_000
const MAX_RECONNECT_ATTEMPTS = 10
/** Token refreshes are capped so a persistently rejected token cannot spin. */
const MAX_REFRESH_ATTEMPTS = 5
const REFRESH_WINDOW_MS = 10 * 60 * 1000

export type ConnectionStatus = 'idle' | 'connecting' | 'connected' | 'disconnected' | 'auth_error'

export interface NewMessageEvent {
  id: string
  senderId: string
  senderUsername: string
  encryptedPayload: string
  timestamp: number
}

export interface StatusDetail {
  /** WebSocket close code, when the status change came from a close. */
  code?: number
  reason?: string
}

export interface RealtimeHandlers {
  /** The detail carries the close code, so the UI can say *why* it dropped. */
  onStatus?: (status: ConnectionStatus, detail?: StatusDetail) => void
  onMessage?: (message: NewMessageEvent) => void
  onTyping?: (senderId: string, isTyping: boolean, groupId?: string) => void
  onRead?: (senderId: string, messageIds: string[], groupId?: string) => void
  /** Asked for a fresh token when the relay reports the current one expired. */
  onTokenRefreshNeeded?: () => Promise<string | null>
}

export class RealtimeClient {
  private ws: WebSocketLike | null = null
  private token: string | null = null
  private manuallyClosed = false
  private reconnectAttempts = 0
  private refreshAttempts = 0
  private lastRefreshAt = 0
  private pingTimer: ReturnType<typeof setInterval> | null = null
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null

  constructor(
    private handlers: RealtimeHandlers = {},
    private createSocket: SocketFactory = defaultSocketFactory
  ) {}

  private setStatus(status: ConnectionStatus, detail?: StatusDetail) {
    this.handlers.onStatus?.(status, detail)
  }

  connect(token: string): void {
    this.token = token
    this.manuallyClosed = false
    this.closeSocket()
    this.setStatus('connecting')

    try {
      // Auth travels as a subprotocol: WebSocket has no header API in browsers
      // or React Native, and a token in the query string would land in logs.
      this.ws = this.createSocket(WS_URL, ['lume', `auth.${token}`], {
        headers: { Origin: APP_ORIGIN },
      })
    } catch {
      this.scheduleReconnect()
      return
    }

    this.ws.onopen = () => {
      this.reconnectAttempts = 0
      this.startPing()
      this.setStatus('connected')
    }

    this.ws.onmessage = event => {
      this.handleFrame(typeof event.data === 'string' ? event.data : '')
    }

    this.ws.onclose = event => {
      this.stopPing()
      const detail: StatusDetail = { code: event.code, reason: event.reason }
      if (this.manuallyClosed) {
        this.setStatus('disconnected', detail)
        return
      }
      void this.handleClose(event.code, detail)
    }

    this.ws.onerror = () => {
      // Always followed by onclose, which owns the recovery decision.
    }
  }

  private async handleClose(code: number, detail: StatusDetail): Promise<void> {
    switch (code) {
      case CloseCodes.EXPIRED_AUTH: {
        const now = Date.now()
        if (now - this.lastRefreshAt > REFRESH_WINDOW_MS) this.refreshAttempts = 0
        if (this.refreshAttempts >= MAX_REFRESH_ATTEMPTS) {
          this.setStatus('auth_error', detail)
          return
        }
        this.refreshAttempts++
        this.lastRefreshAt = now

        const fresh = await this.handlers.onTokenRefreshNeeded?.()
        if (!fresh) {
          this.setStatus('auth_error', detail)
          return
        }
        this.connect(fresh)
        return
      }

      case CloseCodes.MISSING_AUTH:
      case CloseCodes.INVALID_AUTH:
        // Retrying with the same rejected token would only burn rate limit.
        this.setStatus('auth_error', detail)
        return

      case CloseCodes.TOO_MANY_CONNECTIONS:
      case CloseCodes.RATE_LIMITED:
        this.setStatus('disconnected', detail)
        this.scheduleReconnect(MAX_RECONNECT_DELAY_MS)
        return

      default:
        this.setStatus('disconnected', detail)
        this.scheduleReconnect()
    }
  }

  private handleFrame(raw: string): void {
    let parsed: unknown
    try {
      parsed = JSON.parse(raw)
    } catch {
      return
    }
    const type = (parsed as { type?: unknown }).type
    if (typeof type !== 'string') return

    switch (type) {
      case 'new_message': {
        const result = WsNewMessageSchema.safeParse(parsed)
        if (!result.success) return
        const m = result.data
        this.handlers.onMessage?.({
          id: m.messageId,
          senderId: m.senderId,
          senderUsername: m.senderUsername,
          encryptedPayload: m.encryptedPayload,
          timestamp: m.timestamp,
        })
        return
      }
      case 'typing': {
        const result = WsTypingSchema.safeParse(parsed)
        if (!result.success) return
        this.handlers.onTyping?.(result.data.senderId, result.data.isTyping, result.data.groupId)
        return
      }
      case 'read': {
        const result = WsReadReceiptSchema.safeParse(parsed)
        if (!result.success) return
        this.handlers.onRead?.(result.data.senderId, result.data.messageIds, result.data.groupId)
        return
      }
      case 'pong':
        return
      default:
        return
    }
  }

  private send(payload: unknown): void {
    if (this.ws?.readyState === 1) this.ws.send(JSON.stringify(payload))
  }

  sendTyping(recipientId: string, isTyping: boolean, groupId?: string): void {
    this.send({ type: 'typing', recipientId, isTyping, ...(groupId ? { groupId } : {}) })
  }

  sendRead(recipientId: string, messageIds: string[], groupId?: string): void {
    if (messageIds.length === 0) return
    this.send({ type: 'read', recipientId, messageIds, ...(groupId ? { groupId } : {}) })
  }

  private startPing(): void {
    this.stopPing()
    this.pingTimer = setInterval(() => this.send({ type: 'ping' }), PING_INTERVAL_MS)
  }

  private stopPing(): void {
    if (this.pingTimer) clearInterval(this.pingTimer)
    this.pingTimer = null
  }

  /**
   * Reconnect now, from a clean attempt budget.
   *
   * On a phone the backoff runs out for a mundane reason — a tunnel, a lift, a
   * few minutes with the screen off — and once the ten attempts were spent the
   * app stayed offline until it was restarted by hand. Coming back to the
   * foreground, or the OS reporting a network again, is far better evidence that
   * connecting will work than any timer, so both reset the count and retry at
   * once. An auth failure is deliberately still not retried here: the token, not
   * the network, is what has to change.
   */
  resume(): void {
    if (!this.token || this.manuallyClosed) return
    if (this.isConnected) return
    this.reconnectAttempts = 0
    this.clearReconnectTimer()
    this.connect(this.token)
  }

  private scheduleReconnect(forcedDelay?: number): void {
    if (this.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
      this.setStatus('disconnected')
      return
    }
    this.reconnectAttempts++
    const delay =
      forcedDelay ??
      Math.min(MAX_RECONNECT_DELAY_MS, BASE_RECONNECT_DELAY_MS * 2 ** (this.reconnectAttempts - 1))

    this.clearReconnectTimer()
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      if (this.token && !this.manuallyClosed) this.connect(this.token)
    }, delay)
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
  }

  private closeSocket(): void {
    if (!this.ws) return
    this.ws.onopen = null
    this.ws.onmessage = null
    this.ws.onclose = null
    this.ws.onerror = null
    try {
      this.ws.close()
    } catch {
      // Already gone.
    }
    this.ws = null
  }

  disconnect(): void {
    this.manuallyClosed = true
    this.clearReconnectTimer()
    this.stopPing()
    this.closeSocket()
    this.setStatus('disconnected')
  }

  get isConnected(): boolean {
    return this.ws?.readyState === 1
  }
}
