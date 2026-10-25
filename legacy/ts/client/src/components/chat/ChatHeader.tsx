// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import type { Contact } from "@/crypto/storage";
import { t } from "@/lib/i18n";
import { Avatar } from "@/components/ui";
import { SegmentedControl } from "@/components/ui/SegmentedControl";
import { formatTimerLabel, TIMER_OPTIONS } from "./chatUtils";

interface ChatHeaderProps {
  contact: Contact;
  avatarUrl?: string | null;
  isTyping: boolean;
  selfDestructTime: number | null;
  showOptions: boolean;
  onBack: () => void;
  onOpenProfile: () => void;
  onToggleOptions: () => void;
  onSelectTimer: (value: number | null) => void;
}

export default function ChatHeader({
  contact,
  avatarUrl,
  isTyping,
  selfDestructTime,
  showOptions,
  onBack,
  onOpenProfile,
  onToggleOptions,
  onSelectTimer,
}: ChatHeaderProps) {
  return (
    <header className="px-3 sm:px-5 md:px-6 py-3 sm:py-4 border-b border-[var(--border)]/70">
      <div className="flex items-center justify-between gap-2 sm:gap-3">
        <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1">
          <button
            type="button"
            onClick={onBack}
            className="lume-icon-btn md:hidden"
            aria-label={t("chat.back")}
            title={t("chat.back")}
          >
            <svg
              className="w-5 h-5"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M15 19l-7-7 7-7"
              />
            </svg>
          </button>

          <button
            type="button"
            onClick={onOpenProfile}
            className="flex items-center gap-3 min-w-0 hover:bg-[var(--surface-alt)] rounded-[18px] px-2 py-1.5 transition-colors"
          >
            <Avatar src={avatarUrl} username={contact.username} size="lg" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-[var(--text-primary)] truncate">
                @{contact.username}
              </p>
              <div className="mt-0.5 flex items-center gap-2 flex-wrap">
                {isTyping ? (
                  <span className="lume-badge">Typing...</span>
                ) : selfDestructTime ? (
                  <span className="lume-badge">
                    Auto-delete {formatTimerLabel(selfDestructTime)}
                  </span>
                ) : null}
              </div>
            </div>
          </button>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            type="button"
            onClick={onToggleOptions}
            className="lume-icon-btn"
            aria-label={t("chat.options")}
            title={t("chat.options")}
          >
            <svg
              className="w-5 h-5"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 6v.01M12 12v.01M12 18v.01"
              />
            </svg>
          </button>
        </div>
      </div>

      {showOptions ? (
        <div className="mt-4 flex items-center gap-3 flex-wrap reveal-down">
          <span className="text-xs text-[var(--text-muted)]">
            {t("chat.autoDelete")}
          </span>
          <SegmentedControl<number | null>
            options={TIMER_OPTIONS}
            value={selfDestructTime}
            onChange={onSelectTimer}
          />
        </div>
      ) : null}
    </header>
  );
}
