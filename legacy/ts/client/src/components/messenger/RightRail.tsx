// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import { t } from "@/lib/i18n";
import React from 'react';
import type { Chat } from '@/stores';
import type { Contact } from '@/crypto/storage';
import { Avatar } from '@/components/ui';

function AvatarButton({
  contact,
  active,
  onClick,
  avatarUrl,
}: {
  contact: Contact;
  active?: boolean;
  onClick: () => void;
  avatarUrl?: string | null;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`
        w-11 h-11 rounded-full flex items-center justify-center overflow-hidden flex-shrink-0
        [transition:opacity_0.2s_ease]
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]
        ${active ? 'opacity-100 ring-2 ring-[var(--accent)]' : 'opacity-60 hover:opacity-100'}
      `}
      title={contact.username}
      aria-label={contact.username}
    >
      <Avatar src={avatarUrl} username={contact.username} size="md" />
    </button>
  );
}

export default function RightRail({
  contacts,
  chats,
  activeChatId,
  onOpenContact,
  avatarMap,
}: {
  contacts: Contact[];
  chats: Chat[];
  activeChatId: string | null;
  onOpenContact: (contactId: string) => void;
  avatarMap?: Record<string, string>;
}) {
  const contactOrder = [...contacts].sort((a, b) => (b.addedAt ?? 0) - (a.addedAt ?? 0));

  const activeContactId = activeChatId
    ? chats.find((c) => c.id === activeChatId)?.contactId ?? null
    : null;

  return (
    <div className="h-full min-h-0 overflow-hidden">
      <div className="h-full flex flex-col items-center px-3 pt-4 pb-4">
        <p className="text-caption text-[var(--text-muted)] mb-3 flex-shrink-0">{t("contact.list")}</p>
        <div className="flex-1 min-h-0 overflow-y-auto w-full flex flex-col items-center gap-3 pt-1">
          {contactOrder.map((c) => (
            <AvatarButton
              key={c.id}
              contact={c}
              active={activeContactId === c.id}
              onClick={() => onOpenContact(c.id)}
              avatarUrl={avatarMap?.[c.id]}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
