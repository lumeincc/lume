// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useEffect, useState } from "react";
import { t } from "@/lib/i18n";
import { Modal, Avatar } from "@/components/ui";
import { useAuthStore } from "@/stores";
import { profileApi } from "@/lib/api";
import { vaultHasKeys } from "@/crypto/keyVault";

interface OwnProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  username: string | null;
  discoverable: boolean;
  avatarUrl?: string | null;
  online: boolean;
  onEditProfile: () => void;
}

/**
 * Own-profile view — the self-facing mirror of the contact ProfileModal.
 * Presentational only: it shows your identity as others see it and hands off
 * to Settings for editing (no profile mutation happens here).
 */
export default function OwnProfileModal({
  isOpen,
  onClose,
  username,
  discoverable,
  avatarUrl,
  online,
  onEditProfile,
}: OwnProfileModalProps) {
  const userId = useAuthStore((s) => s.userId);
  const [displayName, setDisplayName] = useState("");

  useEffect(() => {
    if (!isOpen || !userId || !vaultHasKeys()) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await profileApi.get(userId);
        if (!cancelled && res.data) setDisplayName(res.data.displayName ?? "");
      } catch {
        // Best-effort — the handle is enough to render the profile.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isOpen, userId]);

  const handle = username ? `@${username}` : "Guest";
  const hasDisplayName = displayName.trim().length > 0;
  const title = hasDisplayName ? displayName.trim() : handle;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={t("modal.profile.title")}>
      <div className="flex flex-col items-center pt-2 pb-4">
        <div className="mb-4">
          <Avatar src={avatarUrl} username={username ?? "U"} size="xl" />
        </div>
        <h2 className="text-base font-semibold text-[var(--text-primary)] mb-1">
          {title}
        </h2>
        <p className="text-xs text-[var(--text-muted)] mb-6 flex items-center gap-1.5">
          <span
            className={`inline-block w-1.5 h-1.5 rounded-full ${online ? "bg-[var(--hl)]" : "bg-[var(--text-muted)]"}`}
            aria-hidden="true"
          />
          {online ? t("modal.profile.online") : t("modal.profile.offline")}
        </p>

        <div className="w-full">
          {hasDisplayName ? (
            <div className="flex items-center justify-between py-3 border-b border-[var(--border)]/55">
              <span className="text-body text-[var(--text-secondary)]">
                {t("common.username")}
              </span>
              <span className="text-body text-[var(--text-muted)]">
                {handle}
              </span>
            </div>
          ) : null}
          <div className="flex items-center justify-between py-3 border-b border-[var(--border)]/55">
            <span className="text-body text-[var(--text-secondary)]">
              {t("modal.profile.discoverable")}
            </span>
            <span className="text-body text-[var(--text-muted)]">
              {discoverable ? t("modal.profile.visible") : t("modal.profile.hidden")}
            </span>
          </div>
        </div>

        <button
          type="button"
          onClick={onEditProfile}
          className="mt-6 w-full py-3 rounded-full border border-[var(--border)] text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--surface-alt)] transition-colors"
        >
          {t("profile.edit")}
        </button>
      </div>
    </Modal>
  );
}
