// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useState } from "react";
import { t } from "@/lib/i18n";
import { Modal, Avatar } from "@/components/ui";
import {
  useContactsStore,
  useBlockedStore,
  type Chat,
} from "@/stores";
import type { Contact } from "@/crypto/storage";
import { authApi } from "@/lib/api";
import { vaultHasKeys } from "@/crypto/keyVault";

interface ProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  contact: Contact;
  chat: Chat;
  safetyNumber: string | null;
  isContactBlocked: boolean;
  onDeleteContact: () => void;
  onHideChat: () => void;
  avatarUrl?: string | null;
}

export default function ProfileModal({
  isOpen,
  onClose,
  contact,
  chat,
  safetyNumber,
  isContactBlocked,
  onDeleteContact,
  onHideChat,
  avatarUrl,
}: ProfileModalProps) {
  const [copiedSafety, setCopiedSafety] = useState(false);
  const [showDeleteContact, setShowDeleteContact] = useState(false);
  const [blockLoading, setBlockLoading] = useState(false);

  const contactId = contact.id;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={t("chat.profile.title")}
    >
      <div className="flex flex-col items-center pt-2 pb-6">
        <div className="mb-4">
          <Avatar src={avatarUrl} username={contact.username} size="xl" />
        </div>
        <h2 className="text-base font-semibold text-[var(--text-primary)] mb-1">
          @{contact.username}
        </h2>
        <p className="text-xs text-[var(--text-muted)] mb-6">{t("contact.lumeUser")}</p>

        {vaultHasKeys() ? (
          <div className="w-full bg-[var(--surface-alt)] rounded-[var(--radius-md)] p-5 border border-[var(--border)] text-center">
            <p className="text-xs text-[var(--text-muted)]">
              {t("chat.profile.safetyNumber")}
            </p>
            {/* The moment that matters: this fingerprint is what proves there
                is no impostor in the middle. Same glow as the deck. */}
            <p className="glow mt-3 text-sm font-semibold tracking-[0.12em] text-[var(--text-primary)] leading-relaxed">
              {safetyNumber}
            </p>

            <div className="mt-4 flex items-center justify-center gap-2 flex-wrap">
              <button
                type="button"
                className="apple-button-secondary px-4"
                onClick={async () => {
                  if (!safetyNumber) return;
                  await navigator.clipboard.writeText(safetyNumber);
                  setCopiedSafety(true);
                  setTimeout(() => setCopiedSafety(false), 1200);
                }}
              >
                {copiedSafety ? t("chat.profile.copied") : t("chat.profile.copy")}
              </button>

              <button
                type="button"
                className={`px-4 py-3 rounded-full border transition-colors text-xs font-semibold ${
                  contact.verified
                    ? "bg-[var(--accent)] text-[var(--accent-contrast)] border-[var(--border)]"
                    : "bg-[var(--surface-strong)] text-[var(--text-secondary)] border-[var(--border)] hover:bg-[var(--surface)]"
                }`}
                onClick={async () => {
                  const nextVerified = !contact.verified;
                  useContactsStore.getState().updateContact(contact.id, {
                    verified: nextVerified,
                    verifiedAt: nextVerified ? Date.now() : undefined,
                  });
                }}
              >
                {contact.verified ? t("chat.profile.verified") : t("chat.profile.markVerified")}
              </button>
            </div>

            <p className="mt-4 text-xs text-[var(--text-muted)]">
              {t("chat.profile.safetyHint")}
            </p>
          </div>
        ) : null}

        {/* Block / Unblock Contact */}
        <button
          type="button"
          disabled={blockLoading}
          className="mt-6 w-full py-3 rounded-full border border-[var(--border)] text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--surface-alt)] transition-colors disabled:opacity-60"
          onClick={async () => {
            if (!contactId || !vaultHasKeys()) return;
            setBlockLoading(true);
            try {
              if (isContactBlocked) {
                await authApi.unblockUser(contactId);
                useBlockedStore.getState().removeBlocked(contactId);
              } else {
                await authApi.blockUser(contactId);
                useBlockedStore.getState().addBlocked(contactId);
              }
            } catch {
              // Best effort — local state still toggles
            } finally {
              setBlockLoading(false);
            }
          }}
        >
          {blockLoading
            ? t('chat.profile.processing')
            : isContactBlocked
              ? t('chat.profile.unblock')
              : t('chat.profile.block')}
        </button>

        <button
          type="button"
          className="mt-4 w-full py-3 rounded-full border border-[var(--border)] text-xs font-semibold text-[var(--text-secondary)] hover:bg-[var(--surface-alt)] transition-colors"
          onClick={onHideChat}
        >
          {chat.isHidden ? t("chat.profile.unhideChat") : t("chat.profile.hideChat")}
        </button>

        {/* Delete contact */}
        {!showDeleteContact ? (
          <button
            type="button"
            className="mt-6 w-full py-3 rounded-full border border-red-500/30 text-red-500 text-xs font-semibold hover:bg-red-500/5 transition-colors"
            onClick={() => setShowDeleteContact(true)}
          >
            {t("contact.delete")}
          </button>
        ) : (
          <div className="mt-6 p-4 rounded-[var(--radius-md)] border border-red-500/30 bg-red-500/5">
            <p className="text-xs text-red-500 mb-3 text-center">
              This will delete the contact, chat history, and encryption session. This cannot be undone.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteContact(false)}
                className="flex-1 apple-button-secondary"
              >
                {t("common.cancel")}
              </button>
              <button
                onClick={onDeleteContact}
                className="flex-1 py-3 rounded-full bg-red-500 text-white text-xs font-semibold hover:bg-red-600 transition-colors"
              >
                {t("common.delete")}
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}
