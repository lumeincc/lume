// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Locks the vault after a period without interaction.
 *
 * Until this existed, unlocking was permanent for the life of the tab: the
 * master key and identity keys sat in the module-scoped vault until the tab was
 * closed. An unattended machine with LUME open was an open conversation, and
 * none of the work protecting the data at rest applied — the 600,000-iteration
 * derivation is irrelevant to an attacker who does not need to derive anything
 * because it has already been derived.
 *
 * **Wall clock, not a timer chain.** The deadline is a timestamp compared on a
 * tick, rather than a `setTimeout` for the full interval. Background tabs have
 * their timers throttled, and a suspended laptop does not fire them at all — so
 * a timer-based lock would let a machine sleep through its own deadline and
 * wake up unlocked, which is the exact scenario this is for.
 *
 * **The vault is cleared before anything else.** Persistence is debounced
 * (`useMessengerSync`), so a save can be in flight when the lock fires. Zeroing
 * the key first means any such save throws in `vaultGetMasterKey` and writes
 * nothing — failing closed. Clearing the in-memory stores first instead would
 * invert that: a pending save would still hold the key and would persist the
 * now-empty stores over the user's real data.
 *
 * **Locking navigates with a full load, not the router.** A reload discards
 * every in-memory remnant — decrypted messages in Zustand, ratchet state,
 * pending timers — in one step whose correctness is obvious. For a security
 * control that matters more than saving the reload.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { vaultClear, vaultHasMasterKey } from "@/crypto/keyVault";
import { wsClient } from "@/lib/websocket";
import { hardNavigate } from "@/lib/hardNavigate";

/** Silence after which the vault locks. */
export const IDLE_LIMIT_MS = 15 * 60 * 1000;

/** How long the warning is shown before the lock actually happens. */
export const IDLE_WARN_MS = 60 * 1000;

/** How often the deadline is checked. */
const TICK_MS = 1000;

/**
 * Events that count as presence.
 *
 * Deliberately not `mousemove`: a resting mouse nudged by a passing lorry is not
 * a user, and on a laptop it fires constantly enough to make the lock
 * unreachable. Scrolling, typing, pointer presses and touches are all
 * unambiguous.
 */
const ACTIVITY_EVENTS = [
  "pointerdown",
  "keydown",
  "touchstart",
  "wheel",
] as const;

export interface IdleLockState {
  /** Seconds left before locking, or `null` when the warning is not showing. */
  secondsLeft: number | null;
  /** Dismisses the warning and restarts the countdown. */
  stayUnlocked: () => void;
}

export function useIdleLock(enabled: boolean): IdleLockState {
  // Zero, not `Date.now()`: reading the clock during render is impure, and on a
  // server-rendered route it would be the *server's* clock, so the first client
  // tick could compare against a deadline set somewhere else entirely. The real
  // deadline is set by `extend()` in the effect below, on the client.
  const deadlineRef = useRef<number>(0);
  const lockedRef = useRef(false);
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);

  const extend = useCallback(() => {
    deadlineRef.current = Date.now() + IDLE_LIMIT_MS;
    setSecondsLeft(null);
  }, []);

  const lock = useCallback(() => {
    // Guard against a second entry: the tick and an event could both reach here.
    if (lockedRef.current) return;
    lockedRef.current = true;

    wsClient.disconnect();
    vaultClear();
    // Full load, not router.replace — see the note at the top of this file.
    hardNavigate("/unlock");
  }, []);

  useEffect(() => {
    if (!enabled) return undefined;

    // The ref directly, not `extend()`: on mount there is no warning to clear,
    // so its setState would be a no-op that still costs a render pass.
    deadlineRef.current = Date.now() + IDLE_LIMIT_MS;

    for (const event of ACTIVITY_EVENTS) {
      window.addEventListener(event, extend, { passive: true });
    }

    const tick = window.setInterval(() => {
      // If the vault emptied by another route — a manual lock, a panic wipe —
      // there is nothing left to protect and the countdown is noise.
      if (!vaultHasMasterKey()) {
        setSecondsLeft(null);
        return;
      }

      const remaining = deadlineRef.current - Date.now();
      if (remaining <= 0) {
        lock();
        return;
      }
      setSecondsLeft(remaining <= IDLE_WARN_MS ? Math.ceil(remaining / 1000) : null);
    }, TICK_MS);

    return () => {
      window.clearInterval(tick);
      for (const event of ACTIVITY_EVENTS) {
        window.removeEventListener(event, extend);
      }
    };
  }, [enabled, extend, lock]);

  return { secondsLeft, stayUnlocked: extend };
}
