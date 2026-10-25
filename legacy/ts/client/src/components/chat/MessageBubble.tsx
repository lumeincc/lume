// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useEffect, useState, useCallback, memo } from "react";
import { t } from "@/lib/i18n";
import type { Message, MessageAttachment } from "@/stores";
import { formatCountdown } from "./chatUtils";
import { filesApi } from "@/lib/api";
import { decryptFile, createFileUrl, formatFileSize, isImageMime } from "@/lib/fileEncryption";
import { vaultHasKeys, vaultGetAttachmentKey } from "@/crypto/keyVault";

function StatusIcon({ status }: { status: Message["status"] }) {
  const base = "w-4 h-4";

  if (status === "sending") {
    return (
      <span className="w-3 h-3 border border-current border-t-transparent rounded-full animate-spin inline-block" />
    );
  }

  if (status === "failed") {
    return (
      <svg
        className={base}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          d="M12 9v4"
        />
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          d="M12 17h.01"
        />
      </svg>
    );
  }

  if (status === "sent") {
    return (
      <svg
        className={base}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          d="M5 12l4 4L19 6"
        />
      </svg>
    );
  }

  if (status === "delivered" || status === "read") {
    return (
      <svg
        className={`${base}${status === "read" ? " text-blue-400" : ""}`}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          d="M3 12l4 4L17 6"
        />
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="2"
          d="M7 12l4 4L21 6"
        />
      </svg>
    );
  }

  return null;
}

function AttachmentView({ attachment }: { attachment: MessageAttachment }) {
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const isImage = isImageMime(attachment.mimeType);

  const handleDownload = useCallback(async () => {
    if (!vaultHasKeys()) return;
    setLoading(true);
    setError(false);
    try {
      const { data, error: dlError } = await filesApi.download(attachment.fileId);
      if (dlError || !data) throw new Error(dlError || 'Download failed');
      const keyInfo = vaultGetAttachmentKey(attachment.fileId);
      if (!keyInfo) throw new Error('Missing attachment decryption key');
      const decrypted = await decryptFile(data.data, keyInfo.nonce, keyInfo.key, attachment.mimeType, attachment.fileName);
      if (!decrypted) throw new Error('Decryption failed');
      const url = createFileUrl(decrypted.data, decrypted.mimeType);
      if (isImage) {
        setImageUrl(url);
      } else {
        const a = document.createElement('a');
        a.href = url;
        a.download = attachment.fileName;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [attachment, isImage]);

  useEffect(() => {
    if (isImage && !imageUrl && !loading && !error) {
      void handleDownload();
    }
  }, [isImage, imageUrl, loading, error, handleDownload]);

  useEffect(() => {
    return () => {
      if (imageUrl) URL.revokeObjectURL(imageUrl);
    };
  }, [imageUrl]);

  if (isImage) {
    return (
      <div className="mb-2 rounded-[var(--radius-md)] overflow-hidden">
        {imageUrl ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={imageUrl} alt={attachment.fileName} className="max-w-full max-h-[300px] rounded-[var(--radius-md)] object-contain" />
        ) : loading ? (
          <div className="w-48 h-32 bg-[var(--surface-strong)] rounded-[var(--radius-md)] flex items-center justify-center">
            <span className="w-5 h-5 border-2 border-current border-t-transparent rounded-full animate-spin text-[var(--text-muted)]" />
          </div>
        ) : error ? (
          <button onClick={handleDownload} className="w-48 h-32 bg-[var(--surface-strong)] rounded-[var(--radius-md)] flex flex-col items-center justify-center gap-1 text-[var(--text-muted)] hover:text-[var(--text-secondary)] transition-colors">
            <span className="text-caption">{t("chat.message.failedToLoad")}</span>
            <span className="text-micro underline">{t("chat.message.retry")}</span>
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <button
      onClick={handleDownload}
      disabled={loading}
      className="mb-2 flex items-center gap-3 px-3 py-2.5 rounded-[var(--radius-md)] bg-[var(--surface-strong)] border border-[var(--border)] hover:bg-[var(--surface)] transition-colors w-full text-left"
    >
      <div className="w-10 h-10 rounded bg-[var(--accent)]/10 flex items-center justify-center flex-shrink-0">
        {loading ? (
          <span className="w-4 h-4 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
        ) : (
          <svg className="w-5 h-5 text-[var(--accent)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M14 2v6h6" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 18v-6m-3 3l3 3 3-3" />
          </svg>
        )}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-[var(--text-primary)] truncate">{attachment.fileName}</p>
        <p className="text-caption text-[var(--text-muted)]">
          {error ? t("chat.message.downloadFailed") : formatFileSize(attachment.size)}
        </p>
      </div>
    </button>
  );
}

function MessageBubble({
  message,
  isMine,
  onDelete,
  onReply,
  replyAuthorName,
}: {
  message: Message;
  isMine: boolean;
  onDelete: (messageId: string) => void;
  onReply: (message: Message) => void;
  replyAuthorName?: string;
}) {
  const [showActions, setShowActions] = useState(false);
  const [remaining, setRemaining] = useState<number | null>(null);
  const timeLabel = new Date(message.timestamp).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
  });

  useEffect(() => {
    // Captured before the guard rather than re-read inside the interval: the
    // closure outlives this render, and `message` can be replaced underneath it.
    const expiresAt = message.selfDestructAt;
    if (!expiresAt) return undefined;
    const update = () => {
      const left = expiresAt - Date.now();
      setRemaining(left > 0 ? left : 0);
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [message.selfDestructAt]);

  useEffect(() => {
    if (remaining !== null && remaining <= 0 && message.selfDestructAt) {
      onDelete(message.id);
    }
  }, [remaining, message.id, message.selfDestructAt, onDelete]);

  return (
    <div className={`message-row group flex ${isMine ? "justify-end message-in-sent" : "justify-start message-in-received"}`}>
      {/* Action buttons — left of own messages */}
      {isMine && (
        <div className="self-center mr-2 flex items-center gap-1 opacity-0 group-hover:opacity-60 transition-opacity">
          <button
            type="button"
            onClick={() => onReply(message)}
            className="hover:!opacity-100 p-1"
            aria-label={t("chat.message.reply")}
            title={t("chat.message.reply")}
          >
            <svg className="w-4 h-4 text-[var(--text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 10l7-7m0 0v14m0-14h4a8 8 0 018 8v5" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => setShowActions(!showActions)}
            className="hover:!opacity-100 p-1"
            aria-label={t("chat.message.delete")}
            title={t("chat.message.delete")}
          >
            <svg className="w-4 h-4 text-[var(--text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0 1 16.138 21H7.862a2 2 0 0 1-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v3M4 7h16" />
            </svg>
          </button>
        </div>
      )}
      <div className="relative max-w-[85%] sm:max-w-[78%]">
        <div
          className={`px-4 py-2.5 ${isMine ? "message-bubble-sent" : "message-bubble-received"}`}
        >
          {/* Reply preview */}
          {message.replyTo && (
            <div className="mb-2 pl-3 border-l-2 border-current/30 rounded-sm">
              <p className="text-caption font-semibold mb-0.5 truncate opacity-90">
                {replyAuthorName || 'Unknown'}
              </p>
              <p className="text-xs opacity-70 truncate leading-snug">
                {message.replyTo.content.length > 80 ? message.replyTo.content.slice(0, 80) + '\u2026' : message.replyTo.content}
              </p>
            </div>
          )}
          {/* Attachment */}
          {message.attachment && <AttachmentView attachment={message.attachment} />}
          {message.content && (
            <p className="break-words text-[15px] leading-relaxed">
              {message.content}
            </p>
          )}
          <div
            className={`flex items-center justify-end gap-1.5 mt-[3px] opacity-45 ${!isMine ? "text-[var(--text-muted)]" : ""}`}
          >
            <span className="text-caption">
              {timeLabel}
            </span>
            {isMine ? <StatusIcon status={message.status} /> : null}
            {message.selfDestructAt ? (
              <span className="inline-flex items-center gap-0.5">
                <svg
                  className="w-3.5 h-3.5"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M12 8v5l3 2"
                  />
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
                {remaining !== null && remaining > 0 ? (
                  <span className="text-micro tracking-[0.04em]">
                    {formatCountdown(remaining)}
                  </span>
                ) : null}
              </span>
            ) : null}
          </div>
        </div>

        {/* Inline delete confirmation */}
        {showActions && (
          <div className="absolute top-0 right-0 -mt-8 flex gap-1 z-10 animate-scale-in origin-bottom-right">
            <button
              type="button"
              onClick={() => {
                onDelete(message.id);
                setShowActions(false);
              }}
              className="px-2 py-1 text-caption font-semibold rounded-md bg-red-500/90 text-white hover:bg-red-600 transition-colors"
            >
              {t("common.delete")}
            </button>
            <button
              type="button"
              onClick={() => setShowActions(false)}
              className="px-2 py-1 text-caption font-semibold rounded-md bg-[var(--surface-strong)] text-[var(--text-secondary)] border border-[var(--border)] hover:bg-[var(--surface)] transition-colors"
            >
              {t("common.cancel")}
            </button>
          </div>
        )}
      </div>
      {/* Action buttons — right of received messages */}
      {!isMine && (
        <div className="self-center ml-2 flex items-center gap-1 opacity-0 group-hover:opacity-60 transition-opacity">
          <button
            type="button"
            onClick={() => onReply(message)}
            className="hover:!opacity-100 p-1"
            aria-label={t("chat.message.reply")}
            title={t("chat.message.reply")}
          >
            <svg className="w-4 h-4 text-[var(--text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 10l7-7m0 0v14m0-14h4a8 8 0 018 8v5" />
            </svg>
          </button>
          <button
            type="button"
            onClick={() => setShowActions(!showActions)}
            className="hover:!opacity-100 p-1"
            aria-label={t("chat.message.delete")}
            title={t("chat.message.delete")}
          >
            <svg className="w-4 h-4 text-[var(--text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0 1 16.138 21H7.862a2 2 0 0 1-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v3M4 7h16" />
            </svg>
          </button>
        </div>
      )}
    </div>
  );
}

export const MessageBubbleMemo = memo(
  MessageBubble,
  (prev, next) =>
    prev.isMine === next.isMine &&
    prev.message.id === next.message.id &&
    prev.message.status === next.message.status &&
    prev.message.content === next.message.content &&
    prev.message.timestamp === next.message.timestamp &&
    prev.message.selfDestructAt === next.message.selfDestructAt &&
    prev.message.replyTo?.messageId === next.message.replyTo?.messageId &&
    prev.message.attachment?.fileId === next.message.attachment?.fileId &&
    prev.replyAuthorName === next.replyAuthorName &&
    prev.onDelete === next.onDelete &&
    prev.onReply === next.onReply,
);

export default MessageBubble;
