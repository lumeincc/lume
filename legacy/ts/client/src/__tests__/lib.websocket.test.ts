// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Tests for lib/websocket.ts
 * Covers: WebSocketClient connect/disconnect, event handling, reconnect, typing, read receipts
 * Uses: jsdom environment for WebSocket global
 */

// @vitest-environment jsdom

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Mock stores before importing wsClient ────────────────────────────────────

const mockSetWsStatus = vi.fn();
const mockSetTyping = vi.fn();
const mockClearAll = vi.fn();

// Track typing state so the auto-clear guard (`if (current)`) works
let typingUsersState: Record<string, boolean> = {};
mockSetTyping.mockImplementation((id: string, isTyping: boolean) => {
  if (isTyping) typingUsersState[id] = true;
  else delete typingUsersState[id];
});
mockClearAll.mockImplementation(() => { typingUsersState = {}; });

vi.mock('@/stores', () => ({
  useUIStore: {
    getState: () => ({ setWsStatus: mockSetWsStatus }),
  },
  useTypingStore: {
    getState: () => ({
      setTyping: mockSetTyping,
      clearAll: mockClearAll,
      get typingUsers() { return typingUsersState; },
    }),
  },
}));

// ── Minimal WebSocket mock ───────────────────────────────────────────────────

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocket.CONNECTING;
  url: string;
  protocols: string | string[];
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  sentMessages: string[] = [];

  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.protocols = protocols || [];
    MockWebSocket._instances.push(this);
  }

  send(data: string) {
    this.sentMessages.push(data);
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
  }

  // Test helpers
  simulateOpen() {
    this.readyState = MockWebSocket.OPEN;
    this.onopen?.(new Event('open'));
  }

  simulateMessage(data: unknown) {
    this.onmessage?.(new MessageEvent('message', { data: JSON.stringify(data) }));
  }

  simulateClose(code = 1000, reason = '') {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({ code, reason } as CloseEvent);
  }

  static _instances: MockWebSocket[] = [];
  static _reset() {
    MockWebSocket._instances = [];
  }
  static get lastInstance() {
    return MockWebSocket._instances[MockWebSocket._instances.length - 1]!;
  }
}

// Attach static constants
Object.defineProperty(MockWebSocket, 'CONNECTING', { value: 0 });
Object.defineProperty(MockWebSocket, 'OPEN', { value: 1 });
Object.defineProperty(MockWebSocket, 'CLOSING', { value: 2 });
Object.defineProperty(MockWebSocket, 'CLOSED', { value: 3 });

// ── Import after mocks ──────────────────────────────────────────────────────

let wsClient: typeof import('@/lib/websocket').wsClient;

beforeEach(async () => {
  vi.useFakeTimers();
  MockWebSocket._reset();
  mockSetWsStatus.mockClear();
  mockSetTyping.mockClear();
  mockSetTyping.mockImplementation((id: string, isTyping: boolean) => {
    if (isTyping) typingUsersState[id] = true;
    else delete typingUsersState[id];
  });
  mockClearAll.mockClear();
  mockClearAll.mockImplementation(() => { typingUsersState = {}; });
  typingUsersState = {};

  // Stub global WebSocket
  vi.stubGlobal('WebSocket', MockWebSocket);
  // Also ensure constants are available
  (globalThis as Record<string, unknown>).WebSocket = MockWebSocket;

  // Re-import to get fresh singleton
  vi.resetModules();
  vi.mock('@/stores', () => ({
    useUIStore: {
      getState: () => ({ setWsStatus: mockSetWsStatus }),
    },
    useTypingStore: {
      getState: () => ({
        setTyping: mockSetTyping,
        clearAll: mockClearAll,
        get typingUsers() { return typingUsersState; },
      }),
    },
  }));

  const mod = await import('@/lib/websocket');
  wsClient = mod.wsClient;
});

afterEach(() => {
  wsClient.disconnect();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

// ── Tests ────────────────────────────────────────────────────────────────────

describe('WebSocketClient', () => {
  describe('connect', () => {
    it('creates WebSocket with correct URL and protocols', async () => {
      const connectPromise = wsClient.connect('test-token');
      const ws = MockWebSocket.lastInstance!;
      expect(ws).toBeDefined();
      expect(ws.url).toBe('ws://localhost:3001/ws');
      expect(ws.protocols).toContain('lume');
      expect(ws.protocols).toContain('auth.test-token');

      ws.simulateOpen();
      await connectPromise;
    });

    it('sets status to connecting then connected', async () => {
      const connectPromise = wsClient.connect('tok');
      expect(mockSetWsStatus).toHaveBeenCalledWith('connecting');

      MockWebSocket.lastInstance.simulateOpen();
      await connectPromise;
      expect(mockSetWsStatus).toHaveBeenCalledWith('connected');
    });

    it('resolves immediately if already connected with same token', async () => {
      const p1 = wsClient.connect('tok');
      const ws = MockWebSocket.lastInstance!;
      ws.simulateOpen();
      await p1;

      // Second connect with same token — should resolve without creating new WS
      const instancesBefore = MockWebSocket._instances.length;
      await wsClient.connect('tok');
      // Should not have created a new instance
      expect(MockWebSocket._instances.length).toBe(instancesBefore);
    });
  });

  describe('disconnect', () => {
    it('closes socket and clears handlers', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      wsClient.disconnect();
      expect(mockSetWsStatus).toHaveBeenCalledWith('disconnected');
      expect(mockClearAll).toHaveBeenCalled();
      expect(wsClient.isConnected()).toBe(false);
    });
  });

  describe('isConnected', () => {
    it('returns false before connecting', () => {
      expect(wsClient.isConnected()).toBe(false);
    });

    it('returns true when open', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;
      expect(wsClient.isConnected()).toBe(true);
    });
  });

  describe('send', () => {
    it('sends JSON-stringified data', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      wsClient.send({ type: 'test', data: 123 });
      const ws = MockWebSocket.lastInstance!;
      expect(ws.sentMessages).toHaveLength(1);
      expect(JSON.parse(ws.sentMessages[0]!)).toEqual({ type: 'test', data: 123 });
    });

    it('does nothing if not connected', () => {
      wsClient.send({ type: 'test' });
      // No error thrown, no messages sent
    });
  });

  describe('sendTyping', () => {
    it('sends typing indicator', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      wsClient.sendTyping('recipient-1', true);
      const sent = JSON.parse(MockWebSocket.lastInstance.sentMessages[0]!);
      expect(sent).toEqual({ type: 'typing', recipientId: 'recipient-1', isTyping: true });
    });
  });

  describe('sendReadReceipt', () => {
    it('sends read receipt with message IDs (batched)', async () => {
      vi.useFakeTimers();
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      wsClient.sendReadReceipt('recipient-1', ['m1', 'm2']);
      // Batched — nothing sent yet
      expect(MockWebSocket.lastInstance.sentMessages).toHaveLength(0);

      vi.advanceTimersByTime(100);
      const sent = JSON.parse(MockWebSocket.lastInstance.sentMessages[0]!);
      expect(sent).toEqual({ type: 'read', recipientId: 'recipient-1', messageIds: ['m1', 'm2'] });
      vi.useRealTimers();
    });

    it('does not send if messageIds is empty', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      wsClient.sendReadReceipt('recipient-1', []);
      expect(MockWebSocket.lastInstance.sentMessages).toHaveLength(0);
    });
  });

  describe('event handling (on/off/emit)', () => {
    it('emits events to registered handlers', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      const handler = vi.fn();
      wsClient.on('new_message', handler);

      // A valid new_message envelope passes Zod validation and is emitted (SEC-20260621-007).
      // The ids are real UUIDs — the schema now enforces that (SEC-20260721-026).
      const msg = {
        type: 'new_message',
        messageId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        senderId: '11111111-1111-4111-8111-111111111111',
        senderUsername: 'alice',
        encryptedPayload: 'cipher',
        timestamp: 123,
      };
      MockWebSocket.lastInstance.simulateMessage(msg);

      expect(handler).toHaveBeenCalledWith(msg);
    });

    it('drops a malformed new_message (fail closed) — handler not called', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      const handler = vi.fn();
      wsClient.on('new_message', handler);

      // Missing required fields → rejected before emit.
      MockWebSocket.lastInstance.simulateMessage({ type: 'new_message', content: 'hello' });

      expect(handler).not.toHaveBeenCalled();
    });

    it('unregisters handlers with off', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      const handler = vi.fn();
      wsClient.on('new_message', handler);
      wsClient.off('new_message', handler);

      MockWebSocket.lastInstance.simulateMessage({ type: 'new_message' });
      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('typing message handling', () => {
    it('updates typing store on typing message', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      MockWebSocket.lastInstance.simulateMessage({
        type: 'typing',
        senderId: '11111111-1111-4111-8111-111111111111',
        senderUsername: 'alice',
        isTyping: true,
      });

      expect(mockSetTyping).toHaveBeenCalledWith('11111111-1111-4111-8111-111111111111', true);
    });

    it('auto-clears typing after 5s timeout', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      MockWebSocket.lastInstance.simulateMessage({
        type: 'typing',
        senderId: '11111111-1111-4111-8111-111111111111',
        senderUsername: 'alice',
        isTyping: true,
      });

      // Advance past 5s typing timeout
      vi.advanceTimersByTime(5100);

      expect(mockSetTyping).toHaveBeenCalledWith('11111111-1111-4111-8111-111111111111', false);
    });

    it('drops a malformed typing event fail-closed (SEC-20260721-025)', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      // Missing senderUsername and a non-UUID senderId — the shape a hostile
      // relay could send. The store must not be touched.
      MockWebSocket.lastInstance.simulateMessage({
        type: 'typing',
        senderId: 'not-a-uuid',
        isTyping: true,
      });

      expect(mockSetTyping).not.toHaveBeenCalled();
    });
  });

  describe('read receipt handling (SEC-20260721-025)', () => {
    it('emits a genuine server-shaped read receipt to handlers', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      const handler = vi.fn();
      wsClient.on('read', handler);

      const evt = {
        type: 'read',
        senderId: '11111111-1111-4111-8111-111111111111',
        messageIds: ['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],
      };
      MockWebSocket.lastInstance.simulateMessage(evt);

      expect(handler).toHaveBeenCalledWith(evt);
    });

    it('drops a malformed read receipt fail-closed', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      const handler = vi.fn();
      wsClient.on('read', handler);

      // No messageIds — rejected before emit.
      MockWebSocket.lastInstance.simulateMessage({
        type: 'read',
        senderId: '11111111-1111-4111-8111-111111111111',
      });

      expect(handler).not.toHaveBeenCalled();
    });
  });

  describe('close code handling', () => {
    it('sets auth_error on MISSING_AUTH (4001)', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      MockWebSocket.lastInstance.simulateClose(4001);
      expect(mockSetWsStatus).toHaveBeenCalledWith('auth_error');
    });

    it('sets auth_error on INVALID_AUTH (4002)', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      MockWebSocket.lastInstance.simulateClose(4002);
      expect(mockSetWsStatus).toHaveBeenCalledWith('auth_error');
    });

    it('sets kicked on TOO_MANY_CONNECTIONS (4005)', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      MockWebSocket.lastInstance.simulateClose(4005);
      expect(mockSetWsStatus).toHaveBeenCalledWith('kicked');
    });

    it('sets rate_limited and schedules reconnect on 4006', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      MockWebSocket.lastInstance.simulateClose(4006);
      expect(mockSetWsStatus).toHaveBeenCalledWith('rate_limited');
    });

    it('calls onTokenExpired handler on EXPIRED_AUTH (4003)', async () => {
      const tokenExpiredHandler = vi.fn();
      wsClient.setTokenExpireHandler(tokenExpiredHandler);

      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      MockWebSocket.lastInstance.simulateClose(4003);
      expect(tokenExpiredHandler).toHaveBeenCalled();
    });

    it('sets auth_error on 4003 if no token handler set', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      MockWebSocket.lastInstance.simulateClose(4003);
      expect(mockSetWsStatus).toHaveBeenCalledWith('auth_error');
    });

    it('attempts reconnect on normal disconnect', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      const instancesBefore = MockWebSocket._instances.length;
      MockWebSocket.lastInstance.simulateClose(1006);

      expect(mockSetWsStatus).toHaveBeenCalledWith('disconnected');

      // Advance timer to trigger reconnect (1s initial delay)
      vi.advanceTimersByTime(1100);
      expect(MockWebSocket._instances.length).toBeGreaterThan(instancesBefore);
    });
  });

  describe('ping', () => {
    it('sends ping every 30s when connected', async () => {
      const p = wsClient.connect('tok');
      MockWebSocket.lastInstance.simulateOpen();
      await p;

      const ws = MockWebSocket.lastInstance!;
      expect(ws.sentMessages).toHaveLength(0);

      vi.advanceTimersByTime(30000);
      expect(ws.sentMessages).toHaveLength(1);
      expect(JSON.parse(ws.sentMessages[0]!)).toEqual({ type: 'ping' });

      vi.advanceTimersByTime(30000);
      expect(ws.sentMessages).toHaveLength(2);
    });
  });
});
