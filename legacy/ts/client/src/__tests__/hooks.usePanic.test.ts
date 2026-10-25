// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// @vitest-environment jsdom
/**
 * Tests for hooks/usePanic.ts
 * Mocks: useAuthStore, useUIStore, and other Zustand stores, wsClient, panicWipe.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';

// ── Hoisted mock state (vi.hoisted runs before module evaluation) ────────────

const mocks = vi.hoisted(() => {
  return {
    mockClearAuth: vi.fn(),
    mockSetPanicMode: vi.fn(),
    mockSetContacts: vi.fn(),
    mockSetChats: vi.fn(),
    mockSetSessions: vi.fn(),
    mockClearAll: vi.fn(),
    mockSetBlockedIds: vi.fn(),
    mockSetShowHiddenChats: vi.fn(),
    mockClearCryptoBanner: vi.fn(),
    mockDisconnect: vi.fn(),
    mockPanicWipe: vi.fn().mockResolvedValue(undefined),
    isPanicMode: false,
  };
});

// ── Helper: create a mock Zustand store function with getState ───────────────

function createMockStore(hookReturn: Record<string, unknown>, stateReturn: Record<string, unknown>) {
  const storeFn = (selector?: (s: unknown) => unknown) => {
    return selector ? selector(hookReturn) : hookReturn;
  };
  storeFn.getState = () => stateReturn;
  return storeFn;
}

// ── Mocks ─────────────────────────────────────────────────────────────────────

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock('@/stores', () => {
  // useUIStore needs a dynamic getter so isPanicMode reflects mocks.isPanicMode at call time
  const useUIStoreFn = (selector?: (s: unknown) => unknown) => {
    const state = { isPanicMode: mocks.isPanicMode, setPanicMode: mocks.mockSetPanicMode };
    return selector ? selector(state) : state;
  };
  useUIStoreFn.getState = () => ({
    setPanicMode: mocks.mockSetPanicMode,
    setShowHiddenChats: mocks.mockSetShowHiddenChats,
    clearCryptoBanner: mocks.mockClearCryptoBanner,
  });

  return {
  useAuthStore: createMockStore(
    { clearAuth: mocks.mockClearAuth },
    { clearAuth: mocks.mockClearAuth },
  ),
  useUIStore: useUIStoreFn,
  useContactsStore: createMockStore(
    { setContacts: mocks.mockSetContacts },
    { setContacts: mocks.mockSetContacts },
  ),
  useChatsStore: createMockStore(
    { setChats: mocks.mockSetChats },
    { setChats: mocks.mockSetChats },
  ),
  useSessionsStore: createMockStore(
    { setSessions: mocks.mockSetSessions },
    { setSessions: mocks.mockSetSessions },
  ),
  useTypingStore: createMockStore(
    { clearAll: mocks.mockClearAll },
    { clearAll: mocks.mockClearAll },
  ),
  useBlockedStore: createMockStore(
    { setBlockedIds: mocks.mockSetBlockedIds },
    { setBlockedIds: mocks.mockSetBlockedIds },
  ),
};});

vi.mock('@/lib/websocket', () => ({
  wsClient: { disconnect: mocks.mockDisconnect },
}));

vi.mock('@/crypto/storage', () => ({
  panicWipe: mocks.mockPanicWipe,
}));

// ── Import after mocks ────────────────────────────────────────────────────────

import { usePanic } from '@/hooks/usePanic';

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('usePanic', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.isPanicMode = false;
    mocks.mockPanicWipe.mockResolvedValue(undefined);
    // Mock window.location.replace
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { ...window.location, replace: vi.fn() },
    });
  });

  it('returns initial state with showPanicConfirm = false', () => {
    const { result } = renderHook(() => usePanic());
    expect(result.current.showPanicConfirm).toBe(false);
    expect(result.current.isPanicMode).toBe(false);
  });

  it('setShowPanicConfirm toggles the confirmation dialog', () => {
    const { result } = renderHook(() => usePanic());

    act(() => {
      result.current.setShowPanicConfirm(true);
    });
    expect(result.current.showPanicConfirm).toBe(true);

    act(() => {
      result.current.setShowPanicConfirm(false);
    });
    expect(result.current.showPanicConfirm).toBe(false);
  });

  it('executePanic: calls setPanicMode(true) first', async () => {
    const { result } = renderHook(() => usePanic());
    await act(async () => {
      await result.current.executePanic();
    });
    expect(mocks.mockSetPanicMode).toHaveBeenCalledWith(true);
  });

  it('executePanic: disconnects WebSocket', async () => {
    const { result } = renderHook(() => usePanic());
    await act(async () => {
      await result.current.executePanic();
    });
    expect(mocks.mockDisconnect).toHaveBeenCalledTimes(1);
  });

  it('executePanic: calls panicWipe', async () => {
    const { result } = renderHook(() => usePanic());
    await act(async () => {
      await result.current.executePanic();
    });
    expect(mocks.mockPanicWipe).toHaveBeenCalledTimes(1);
  });

  it('executePanic: resets all Zustand stores via getState()', async () => {
    const { result } = renderHook(() => usePanic());
    await act(async () => {
      await result.current.executePanic();
    });
    expect(mocks.mockClearAuth).toHaveBeenCalledTimes(1);
    expect(mocks.mockSetContacts).toHaveBeenCalledWith([]);
    expect(mocks.mockSetChats).toHaveBeenCalledWith([]);
    expect(mocks.mockSetSessions).toHaveBeenCalledWith({});
    expect(mocks.mockClearAll).toHaveBeenCalledTimes(1);
    expect(mocks.mockSetBlockedIds).toHaveBeenCalledWith([]);
    expect(mocks.mockSetShowHiddenChats).toHaveBeenCalledWith(false);
    expect(mocks.mockClearCryptoBanner).toHaveBeenCalledTimes(1);
  });

  it('executePanic: redirects via window.location.replace("/")', async () => {
    const { result } = renderHook(() => usePanic());
    await act(async () => {
      await result.current.executePanic();
    });
    expect(window.location.replace).toHaveBeenCalledWith('/');
  });

  it('executePanic: correct call order — setPanicMode -> disconnect -> clearAuth -> panicWipe -> location.replace', async () => {
    const callOrder: string[] = [];
    mocks.mockSetPanicMode.mockImplementation(() => callOrder.push('setPanicMode'));
    mocks.mockDisconnect.mockImplementation(() => callOrder.push('disconnect'));
    mocks.mockPanicWipe.mockImplementation(async () => callOrder.push('panicWipe'));
    mocks.mockClearAuth.mockImplementation(() => callOrder.push('clearAuth'));
    (window.location.replace as ReturnType<typeof vi.fn>).mockImplementation(() => callOrder.push('replace'));

    const { result } = renderHook(() => usePanic());
    await act(async () => {
      await result.current.executePanic();
    });

    // setPanicMode and disconnect happen before anything destructive
    expect(callOrder.indexOf('setPanicMode')).toBeLessThan(callOrder.indexOf('clearAuth'));
    expect(callOrder.indexOf('disconnect')).toBeLessThan(callOrder.indexOf('clearAuth'));
    // vault is cleared BEFORE storage is wiped (SEC-20260621-016)
    expect(callOrder.indexOf('clearAuth')).toBeLessThan(callOrder.indexOf('panicWipe'));
    // replace happens last
    expect(callOrder.indexOf('panicWipe')).toBeLessThan(callOrder.indexOf('replace'));
  });

  it('exposes isPanicMode from UIStore', () => {
    mocks.isPanicMode = true;
    const { result } = renderHook(() => usePanic());
    expect(result.current.isPanicMode).toBe(true);
  });
});
