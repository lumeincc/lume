// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useId, useState } from "react";
import { t } from "@/lib/i18n";
import { Popover } from "@/components/ui/Popover";

interface AddContactPopoverProps {
  open: boolean;
  onClose: () => void;
  anchorRef: React.RefObject<HTMLElement | null>;
  /** Resolves true on success (so the popover can close itself). */
  onSubmit: (username: string) => Promise<boolean>;
  error?: string;
  loading?: boolean;
  align?: "start" | "end";
}

/**
 * The "start chat" form as a compact popover that grows out of its trigger
 * button, instead of a full-screen dialog.
 */
export default function AddContactPopover({
  open,
  onClose,
  anchorRef,
  onSubmit,
  error,
  loading,
  align = "end",
}: AddContactPopoverProps) {
  // Rendered inside ChatListPanel, which the chats page mounts twice (mobile and
  // desktop trees, one hidden by CSS). With a fixed id the label would resolve to
  // whichever copy came first in the document — possibly the hidden one.
  const fieldId = useId();
  const [username, setUsername] = useState("");

  // Clear the field whenever the popover opens or closes (derived-state reset —
  // React's recommended alternative to a reset-in-effect).
  const [prevOpen, setPrevOpen] = useState(open);
  if (prevOpen !== open) {
    setPrevOpen(open);
    setUsername("");
  }

  const submit = async () => {
    if (!username || loading) return;
    const ok = await onSubmit(username);
    if (ok) onClose();
  };

  return (
    <Popover open={open} onClose={onClose} anchorRef={anchorRef} align={align} width={288}>
      <label
        htmlFor={fieldId}
        className="block px-1.5 pt-1 pb-2 text-xs font-semibold text-[var(--text-secondary)]"
      >
        {t("contact.startChat")}
      </label>
      <input
        id={fieldId}
        name="add-contact-username"
        autoFocus
        value={username}
        onChange={(e) =>
          setUsername(
            e.target.value
              .replace(/^@+/, "")
              .replace(/[^a-zA-Z0-9_]/g, "")
              .slice(0, 32),
          )
        }
        onKeyDown={(e) => {
          if (e.key === "Enter") void submit();
        }}
        placeholder={t("modal.addContact.usernamePlaceholder")}
        aria-label={t("modal.addContact.usernameAria")}
        className="w-full px-3 py-2.5 rounded-[10px] bg-[var(--surface-alt)] border border-[var(--border)] text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
      />
      {error ? (
        <p className="px-1 pt-1.5 text-caption text-red-500">{error}</p>
      ) : null}
      <button
        type="button"
        onClick={() => void submit()}
        disabled={!username || loading}
        className="mt-2 w-full py-2.5 rounded-[10px] bg-[var(--accent)] text-[var(--accent-contrast)] text-body font-semibold hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? t("modal.addContact.starting") : t("modal.addContact.start")}
      </button>
    </Popover>
  );
}
