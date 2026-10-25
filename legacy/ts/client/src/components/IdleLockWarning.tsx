// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { t } from "@/lib/i18n";

/**
 * The minute of notice before the vault locks itself.
 *
 * A lock that arrives without warning reads as a crash — the screen you were
 * looking at is replaced by a PIN prompt with no explanation, and the natural
 * conclusion is that the app dropped your session. Saying so first, with the
 * count visible, turns the same event into something the product did on purpose.
 *
 * Any interaction anywhere dismisses this, because `useIdleLock` treats a
 * keypress or a pointer press as presence. The button is for the case where the
 * user has read the warning and wants to say so without touching the
 * conversation underneath.
 */
export default function IdleLockWarning({
  secondsLeft,
  onStayUnlocked,
}: {
  secondsLeft: number | null;
  onStayUnlocked: () => void;
}) {
  if (secondsLeft === null) return null;

  return (
    <div
      // `alert` rather than `dialog`: this must not steal focus from whatever
      // the user is doing — moving focus would itself be an interruption, and
      // the whole point is that carrying on dismisses it.
      role="alert"
      aria-live="assertive"
      className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 flex items-center gap-4 px-5 py-3 rounded-2xl border border-[var(--border)] bg-[var(--surface)] shadow-lg animate-fade-in"
    >
      <div className="flex flex-col">
        <span className="text-sm text-[var(--text-primary)]">
          {t("lock.warningTitle")}
        </span>
        <span className="text-xs text-[var(--text-muted)] tabular-nums">
          {t("lock.warningBody", { seconds: secondsLeft })}
        </span>
      </div>
      <button
        onClick={onStayUnlocked}
        className="text-sm px-3 py-1.5 rounded-full border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--surface-alt)] transition-colors whitespace-nowrap"
      >
        {t("lock.stayUnlocked")}
      </button>
    </div>
  );
}
