// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

// @vitest-environment jsdom
/**
 * The vault locks itself after a period without interaction.
 *
 * Until this existed, unlocking lasted as long as the tab. An unattended machine
 * with LUME open was an open conversation, and none of the at-rest protection
 * applied — an attacker does not need to derive a key that is already derived.
 *
 * The case worth the most care is the sleeping laptop. A `setTimeout` for the
 * full interval does not fire while a machine is suspended, so a timer-based
 * lock would wake up unlocked — precisely the scenario the feature exists for.
 * The implementation compares a wall-clock deadline instead, and the test below
 * jumps the clock past the deadline without ever letting the interval run
 * in-between, which is what suspension looks like from the page's side.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";

// Declared through `vi.hoisted` because `vi.mock` factories are lifted above
// ordinary top-level consts — referencing a plain `const` from one is a
// use-before-initialisation error at import time.
const mocks = vi.hoisted(() => ({
  disconnect: vi.fn(),
  vaultClear: vi.fn(),
  hardNavigate: vi.fn(),
  state: { hasMasterKey: true },
}));
const { disconnect, vaultClear, hardNavigate: assign } = mocks;

vi.mock("@/lib/websocket", () => ({ wsClient: { disconnect: mocks.disconnect } }));
vi.mock("@/crypto/keyVault", () => ({
  vaultClear: mocks.vaultClear,
  vaultHasMasterKey: () => mocks.state.hasMasterKey,
}));
vi.mock("@/lib/hardNavigate", () => ({ hardNavigate: mocks.hardNavigate }));

import { useIdleLock, IDLE_LIMIT_MS, IDLE_WARN_MS } from "@/hooks/useIdleLock";

beforeEach(() => {
  vi.useFakeTimers();
  disconnect.mockClear();
  vaultClear.mockClear();
  assign.mockClear();
  mocks.state.hasMasterKey = true;
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useIdleLock", () => {
  it("does nothing while the user is inside the idle window", () => {
    renderHook(() => useIdleLock(true));

    act(() => {
      vi.advanceTimersByTime(IDLE_LIMIT_MS - IDLE_WARN_MS - 5000);
    });

    expect(assign).not.toHaveBeenCalled();
    expect(vaultClear).not.toHaveBeenCalled();
  });

  it("warns before locking, counting down in seconds", () => {
    const { result } = renderHook(() => useIdleLock(true));

    act(() => {
      vi.advanceTimersByTime(IDLE_LIMIT_MS - IDLE_WARN_MS + 1000);
    });

    expect(result.current.secondsLeft).toBeGreaterThan(0);
    expect(result.current.secondsLeft).toBeLessThanOrEqual(IDLE_WARN_MS / 1000);
    // Warning only — nothing has been torn down yet.
    expect(vaultClear).not.toHaveBeenCalled();
  });

  it("locks once the deadline passes, clearing the vault before navigating", () => {
    renderHook(() => useIdleLock(true));

    act(() => {
      vi.advanceTimersByTime(IDLE_LIMIT_MS + 1000);
    });

    expect(disconnect).toHaveBeenCalled();
    expect(vaultClear).toHaveBeenCalled();
    expect(assign).toHaveBeenCalledWith("/unlock");

    // Order matters and is the whole reason the lock is written this way: a
    // debounced save still holding the master key would persist emptied stores
    // over real data. Clearing first makes any such save throw instead.
    const clearOrder = vaultClear.mock.invocationCallOrder[0] ?? Infinity;
    const assignOrder = assign.mock.invocationCallOrder[0] ?? -Infinity;
    expect(clearOrder).toBeLessThan(assignOrder);
  });

  it("locks a machine that was asleep past its deadline", () => {
    // No interval ticks during the jump — the page is suspended, timers frozen.
    // A setTimeout-based lock would simply never fire; the wall-clock deadline
    // is caught on the first tick after waking.
    renderHook(() => useIdleLock(true));

    const wokeAt = Date.now() + IDLE_LIMIT_MS * 4;
    vi.setSystemTime(wokeAt);

    act(() => {
      vi.advanceTimersByTime(1000);
    });

    expect(assign).toHaveBeenCalledWith("/unlock");
  });

  it("an interaction restarts the countdown", () => {
    const { result } = renderHook(() => useIdleLock(true));

    act(() => {
      vi.advanceTimersByTime(IDLE_LIMIT_MS - 2000);
    });
    expect(result.current.secondsLeft).not.toBeNull();

    act(() => {
      window.dispatchEvent(new Event("keydown"));
    });
    expect(result.current.secondsLeft).toBeNull();

    // Past the *original* deadline; the key press moved it.
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(assign).not.toHaveBeenCalled();
  });

  it("the stay-unlocked button restarts the countdown too", () => {
    const { result } = renderHook(() => useIdleLock(true));

    act(() => {
      vi.advanceTimersByTime(IDLE_LIMIT_MS - 2000);
    });
    expect(result.current.secondsLeft).not.toBeNull();

    act(() => {
      result.current.stayUnlocked();
    });
    expect(result.current.secondsLeft).toBeNull();

    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(assign).not.toHaveBeenCalled();
  });

  it("does not run at all when the session is not authenticated", () => {
    renderHook(() => useIdleLock(false));

    act(() => {
      vi.advanceTimersByTime(IDLE_LIMIT_MS * 3);
    });

    expect(assign).not.toHaveBeenCalled();
    expect(vaultClear).not.toHaveBeenCalled();
  });

  it("stays quiet when the vault is already empty", () => {
    // A manual lock or a panic wipe emptied it. There is nothing left to
    // protect, and a countdown over an already-locked vault is noise.
    mocks.state.hasMasterKey = false;
    const { result } = renderHook(() => useIdleLock(true));

    act(() => {
      vi.advanceTimersByTime(IDLE_LIMIT_MS + 5000);
    });

    expect(result.current.secondsLeft).toBeNull();
    expect(assign).not.toHaveBeenCalled();
  });

  it("locks only once even if the interval keeps running", () => {
    renderHook(() => useIdleLock(true));

    act(() => {
      vi.advanceTimersByTime(IDLE_LIMIT_MS + 10_000);
    });

    expect(assign).toHaveBeenCalledTimes(1);
    expect(vaultClear).toHaveBeenCalledTimes(1);
  });
});
