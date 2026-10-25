// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Sound notifications for incoming messages.
 * Uses the Web Audio API to generate a short notification tone
 * without requiring an external audio file.
 */

let audioContext: AudioContext | null = null;
let soundEnabled = true;

/**
 * Enable or disable notification sounds globally.
 */
export function setSoundEnabled(enabled: boolean): void {
  soundEnabled = enabled;
  if (typeof window !== 'undefined') {
    try {
      localStorage.setItem('lume:sound', enabled ? '1' : '0');
    } catch { /* ignore */ }
  }
}

/**
 * Check whether notification sounds are enabled.
 */
export function isSoundEnabled(): boolean {
  return soundEnabled;
}

/**
 * Initialise from persisted preference. Call once on app boot.
 */
export function initSoundPreference(): void {
  if (typeof window === 'undefined') return;
  try {
    const stored = localStorage.getItem('lume:sound');
    soundEnabled = stored !== '0';
  } catch {
    soundEnabled = true;
  }
}

/**
 * Play a short, pleasant notification tone.
 * Uses Web Audio API — no external sound file needed.
 * Does nothing when:
 *  - sounds are disabled
 *  - the tab is focused AND the chat is active (the user is reading already)
 *  - window/AudioContext not available
 */
export function playMessageSound(options?: { force?: boolean }): void {
  if (typeof window === 'undefined') return;
  if (!soundEnabled && !options?.force) return;

  try {
    if (!audioContext) {
      audioContext = new AudioContext();
    }

    // Resume the context if it's in a suspended state (autoplay policy)
    if (audioContext.state === 'suspended') {
      void audioContext.resume();
    }

    const ctx = audioContext;
    const now = ctx.currentTime;

    // Create a two-tone chime (C5 → E5) — soft & short
    const osc1 = ctx.createOscillator();
    const osc2 = ctx.createOscillator();
    const gain = ctx.createGain();

    osc1.type = 'sine';
    osc1.frequency.setValueAtTime(523.25, now); // C5

    osc2.type = 'sine';
    osc2.frequency.setValueAtTime(659.25, now); // E5

    gain.gain.setValueAtTime(0, now);
    gain.gain.linearRampToValueAtTime(0.15, now + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);

    osc1.connect(gain);
    osc2.connect(gain);
    gain.connect(ctx.destination);

    osc1.start(now);
    osc2.start(now + 0.08);
    osc1.stop(now + 0.35);
    osc2.stop(now + 0.35);
  } catch {
    // Audio not supported — silently ignore
  }
}
