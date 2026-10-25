// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useId, useRef } from "react";
import { t } from "@/lib/i18n";
import type { Message } from "@/stores";
import type { Contact } from "@/crypto/storage";
import { formatTimerLabel } from "./chatUtils";
import { MAX_FILE_SIZE, formatFileSize } from "@/lib/fileEncryption";

export interface PendingAttachment {
  file: File;
  preview?: string; // Object URL for images
}

interface ChatInputProps {
  messageText: string;
  sending: boolean;
  selfDestructTime: number | null;
  replyingTo: Message | null;
  userId: string | null;
  contact: Contact | undefined;
  attachment?: PendingAttachment | null;
  onMessageChange: (text: string) => void;
  onSend: () => void;
  onKeyDown: (e: React.KeyboardEvent) => void;
  onToggleOptions: () => void;
  onCancelReply: () => void;
  onAttach?: (file: File) => void;
  onCancelAttachment?: () => void;
}

export default function ChatInput({
  messageText,
  sending,
  selfDestructTime,
  replyingTo,
  userId,
  contact,
  attachment,
  onMessageChange,
  onSend,
  onKeyDown,
  onToggleOptions,
  onCancelReply,
  onAttach,
  onCancelAttachment,
}: ChatInputProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  // The chat page renders one tree for mobile and one for desktop and hides the
  // other with CSS, so this component is mounted twice at once. A fixed `id`
  // would exist twice in the document.
  const fieldId = useId();

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !onAttach) return;
    if (file.size > MAX_FILE_SIZE) {
      alert(`File too large. Max size: ${formatFileSize(MAX_FILE_SIZE)}`);
      return;
    }
    onAttach(file);
    // Reset the file input so the same file can be re-selected
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <footer className="px-3 sm:px-5 md:px-6 py-3 sm:py-4 border-t border-[var(--border)]/70">
      {/* Attachment preview */}
      {attachment && (
        <div className="mb-3 flex items-center gap-3 px-4 py-2.5 rounded-[var(--radius-md)] bg-[var(--surface-alt)] border border-[var(--border)]">
          {attachment.preview ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={attachment.preview} alt={t("chat.attachmentPreview")} className="w-12 h-12 rounded object-cover" />
          ) : (
            <div className="w-12 h-12 rounded bg-[var(--surface-strong)] flex items-center justify-center">
              <svg className="w-6 h-6 text-[var(--text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M14 2v6h6" />
              </svg>
            </div>
          )}
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-[var(--text-primary)] truncate">{attachment.file.name}</p>
            <p className="text-caption text-[var(--text-muted)]">{formatFileSize(attachment.file.size)}</p>
          </div>
          <button
            type="button"
            onClick={onCancelAttachment}
            className="flex-shrink-0 p-1 rounded-full hover:bg-[var(--surface-strong)] transition-colors"
            aria-label={t("chat.removeAttachment")}
          >
            <svg className="w-4 h-4 text-[var(--text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}
      {/* Reply bar */}
      {replyingTo && (
        <div className="mb-3 flex items-start gap-3 px-4 py-2.5 rounded-[var(--radius-md)] bg-[var(--surface-alt)] border border-[var(--border)]">
          <div className="flex-1 min-w-0 pl-3 border-l-2 border-[var(--accent)]">
            <p className="text-caption font-semibold text-[var(--accent)] mb-0.5">
              {replyingTo.senderId === userId ? t("chat.replyToYou") : (contact?.username || t("chat.replyToUnknown"))}
            </p>
            <p className="text-xs text-[var(--text-secondary)] truncate">
              {replyingTo.content.length > 100 ? replyingTo.content.slice(0, 100) + '\u2026' : replyingTo.content}
            </p>
          </div>
          <button
            type="button"
            onClick={onCancelReply}
            className="flex-shrink-0 p-1 rounded-full hover:bg-[var(--surface-strong)] transition-colors"
            aria-label={t("chat.cancelReply")}
          >
            <svg className="w-4 h-4 text-[var(--text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}
      <div className="flex items-end gap-3">
        <div className="flex-1">
          <textarea
            id={`${fieldId}-message`}
            name="message"
            value={messageText}
            onChange={(e) => onMessageChange(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder={contact?.username ? t("chat.messagePlaceholder", { username: contact.username }) : t("chat.messagePlaceholderPlain")}
            rows={1}
            maxLength={10000}
            aria-label={t("chat.messageInputAria")}
            className="w-full px-2 py-2.5 bg-transparent text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none resize-none text-base leading-snug"
            style={{ minHeight: "48px", maxHeight: "140px" }}
          />
        </div>
        {onAttach && (
          <>
            <input
              ref={fileInputRef}
              id={`${fieldId}-attachment`}
              name="chat-attachment"
              type="file"
              onChange={handleFileSelect}
              accept="image/*,.pdf,.doc,.docx,.txt,.zip"
              className="hidden"
              aria-hidden="true"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="w-10 h-10 rounded-full text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-alt)] transition-colors inline-flex items-center justify-center flex-shrink-0"
              aria-label={t("chat.attachFile")}
              title={t("chat.attachFile")}
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M21.44 11.05l-9.19 9.19a6 6 0 01-8.49-8.49l9.19-9.19a4 4 0 015.66 5.66l-9.2 9.19a2 2 0 01-2.83-2.83l8.49-8.48" />
              </svg>
            </button>
          </>
        )}
        <button
          type="button"
          onClick={onToggleOptions}
          className={`w-10 h-10 rounded-full transition-colors inline-flex items-center justify-center flex-shrink-0 ${
            selfDestructTime
              ? "bg-[var(--surface-alt)] text-[var(--text-primary)]"
              : "text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-alt)]"
          }`}
          aria-label={t("chat.selfDestructTimer")}
          title={
            selfDestructTime
              ? t("chat.autoDelete", { timer: formatTimerLabel(selfDestructTime) })
              : t("chat.selfDestructTimer")
          }
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v5l3 2" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </button>
        <button
          type="button"
          onClick={onSend}
          disabled={(!messageText.trim() && !attachment) || sending}
          className="w-11 h-11 rounded-full bg-[var(--accent)] text-[var(--accent-contrast)] hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-40 disabled:cursor-not-allowed inline-flex items-center justify-center flex-shrink-0"
          aria-label={t("chat.send")}
          title={t("chat.send")}
        >
          {sending ? (
            <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
          ) : (
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
                d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
              />
            </svg>
          )}
        </button>
      </div>

      {selfDestructTime ? (
        <div className="mt-2 text-center">
          <span className="text-xs text-[var(--text-muted)]">
            Auto-delete in {formatTimerLabel(selfDestructTime)}
          </span>
        </div>
      ) : null}
    </footer>
  );
}
