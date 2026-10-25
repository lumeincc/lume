// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import React, { memo, useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { Chat } from '@/stores';
import { useBlockedStore, useChatsStore, useGroupsStore, useUIStore } from '@/stores';
import type { GroupData } from '@/lib/api';
import { loadSettings, verifyHiddenChatPin, isLegacyHiddenPinHash, hashHiddenChatPin, saveSettings, type Contact } from '@/crypto/storage';
import { vaultGetMasterKey, vaultHasMasterKey } from '@/crypto/keyVault';
import { Avatar, Button, Input, Modal } from '@/components/ui';
import AddContactPopover from '@/components/modals/AddContactPopover';
import { t } from '@/lib/i18n';
import { MIN_PIN_LENGTH } from '@/lib/pinPolicy';

function formatTime(timestamp?: number) {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  }
  return date.toLocaleDateString('en-US', { day: 'numeric', month: 'short' });
}

const ChatRow = memo(function ChatRow({
  chat,
  contact,
  selected,
  onClick,
  showHiddenControls,
  onToggleHidden,
  searchHighlight,
  avatarUrl,
}: {
  chat: Chat;
  contact: Contact;
  selected: boolean;
  onClick: () => void;
  showHiddenControls: boolean;
  onToggleHidden: (chatId: string) => void;
  searchHighlight?: string;
  avatarUrl?: string | null;
}) {
  const timeLabel = formatTime(chat.lastMessage?.timestamp);
  const isBlocked = useBlockedStore((s) => !!s.blockedIds[contact.id]);
  const matchedMessage = searchHighlight
    ? chat.messages.find((m) => m.content.toLowerCase().includes(searchHighlight))
    : null;
  const preview = isBlocked
    ? t("chatList.blocked")
    : matchedMessage
      ? matchedMessage.content
      : (chat.lastMessage?.content || t("chatList.startMessaging"));

  return (
    <button
      type="button"
      onClick={onClick}
      className={`
        relative w-full px-4 py-3.5 sm:py-3 text-left transition-colors
        border-b border-[var(--border)]/55 last:border-b-0
        min-h-[56px] sm:min-h-0
        ${selected ? 'bg-[var(--surface-strong)] text-[var(--text-primary)]' : 'hover:bg-[var(--surface-alt)] active:bg-[var(--surface-strong)] text-[var(--text-primary)]'}
      `}
    >
      {selected ? <span className="absolute left-0 top-0 bottom-0 w-[2px] bg-[var(--text-muted)]" aria-hidden="true" /> : null}
      <div className="flex items-center gap-3">
        <Avatar src={avatarUrl} username={contact.username} size="lg" />

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="truncate text-body font-semibold text-[var(--text-primary)]">
                @{contact.username}
              </p>
              <p className="truncate text-xs mt-0.5 text-[var(--text-secondary)]">
                {preview}
              </p>
            </div>
            <div className="flex flex-col items-end gap-2 flex-shrink-0">
              {timeLabel ? (
                <span className="text-caption text-[var(--text-muted)]">
                  {timeLabel}
                </span>
              ) : null}
              {showHiddenControls ? (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    onToggleHidden(chat.id);
                  }}
                  className="w-6 h-6 rounded-full border border-[var(--border)] bg-[var(--surface)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-alt)] transition-colors inline-flex items-center justify-center"
                  aria-label={chat.isHidden ? t("chatList.unhideChat") : t("chatList.hideChat")}
                  title={chat.isHidden ? t("chatList.unhideChat") : t("chatList.hideChat")}
                >
                  {chat.isHidden ? (
                    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M13.875 18.825A10.05 10.05 0 0112 19C7 19 2.73 15.11 1 12c.52-.94 1.19-1.82 1.97-2.62M9.9 4.24A9.96 9.96 0 0112 4c5 0 9.27 3.89 11 8a14.56 14.56 0 01-4.2 4.91M15 12a3 3 0 10-4.24 2.73" />
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M3 3l18 18" />
                    </svg>
                  ) : (
                    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M1 12c1.73-3.11 6-7 11-7s9.27 3.89 11 7c-1.73 3.11-6 7-11 7S2.73 15.11 1 12z" />
                      <circle cx="12" cy="12" r="3" strokeWidth="1.8" />
                    </svg>
                  )}
                </button>
              ) : null}
              {chat.unreadCount > 0 ? (
                <span
                  className={`
                    min-w-5 h-5 px-1.5 rounded-full text-caption font-semibold flex items-center justify-center
                    bg-[var(--accent)] text-[var(--accent-contrast)]
                  `}
                >
                  {chat.unreadCount > 9 ? '9+' : chat.unreadCount}
                </span>
              ) : null}
            </div>
          </div>
        </div>
      </div>
    </button>
  );
}, (prev, next) =>
  prev.chat.id === next.chat.id &&
  prev.chat.lastMessage?.id === next.chat.lastMessage?.id &&
  prev.chat.lastMessage?.status === next.chat.lastMessage?.status &&
  prev.chat.unreadCount === next.chat.unreadCount &&
  prev.chat.isHidden === next.chat.isHidden &&
  prev.contact.id === next.contact.id &&
  prev.contact.username === next.contact.username &&
  prev.selected === next.selected &&
  prev.showHiddenControls === next.showHiddenControls &&
  prev.searchHighlight === next.searchHighlight &&
  prev.avatarUrl === next.avatarUrl
);

const GroupRow = memo(function GroupRow({
  group,
  selected,
  onClick,
  unread = 0,
}: {
  group: GroupData;
  selected: boolean;
  onClick: () => void;
  unread?: number;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`
        relative w-full px-4 py-3.5 sm:py-3 text-left transition-colors
        border-b border-[var(--border)]/55 last:border-b-0
        min-h-[56px] sm:min-h-0
        ${selected ? 'bg-[var(--surface-strong)] text-[var(--text-primary)]' : 'hover:bg-[var(--surface-alt)] active:bg-[var(--surface-strong)] text-[var(--text-primary)]'}
      `}
    >
      {selected ? <span className="absolute left-0 top-0 bottom-0 w-[2px] bg-[var(--text-muted)]" aria-hidden="true" /> : null}
      <div className="flex items-center gap-3">
        <div
          className={`
            w-11 h-11 rounded-full border flex items-center justify-center flex-shrink-0
            shadow-[var(--shadow-sm)]
            ${selected ? 'border-[var(--accent)]/35 bg-[var(--surface)]' : 'border-[var(--border)] bg-[var(--surface)]'}
          `}
        >
          <svg className="w-5 h-5 text-[var(--text-muted)]" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4-4v2" />
            <circle cx="9" cy="7" r="4" strokeWidth="1.8" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M23 21v-2a4 4 0 00-3-3.87" />
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M16 3.13a4 4 0 010 7.75" />
          </svg>
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="truncate text-body font-semibold text-[var(--text-primary)]">
                {group.name}
              </p>
              <p className="truncate text-xs mt-0.5 text-[var(--text-secondary)]">
                {t('group.memberCount', { count: group.members.length })}
              </p>
            </div>
            {unread > 0 ? (
              <span className="min-w-5 h-5 px-1.5 rounded-full text-caption font-semibold flex items-center justify-center bg-[var(--accent)] text-[var(--accent-contrast)] flex-shrink-0">
                {unread > 9 ? '9+' : unread}
              </span>
            ) : null}
          </div>
        </div>
      </div>
    </button>
  );
}, (prev, next) =>
  prev.group.id === next.group.id &&
  prev.group.name === next.group.name &&
  prev.group.members.length === next.group.members.length &&
  prev.selected === next.selected &&
  prev.unread === next.unread
);

export default function ChatListPanel({
  chats,
  contacts,
  selectedChatId,
  searchQuery,
  onSearchChange,
  onSelectChat,
  onAddContact,
  addContactError,
  addContactLoading,
  onClearAddContactError,
  onNewGroup,
  avatarMap,
}: {
  chats: Chat[];
  contacts: Contact[];
  selectedChatId: string | null;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  onSelectChat: (chatId: string) => void;
  onAddContact: (username: string) => Promise<boolean>;
  addContactError: string;
  addContactLoading: boolean;
  onClearAddContactError?: () => void;
  onNewGroup?: () => void;
  avatarMap?: Record<string, string>;
}) {
  const router = useRouter();
  // This panel is mounted twice at once — the chats page renders a mobile tree
  // and a desktop tree and hides one with CSS — so a fixed field id would exist
  // twice in the document.
  const fieldId = useId();
  // Opening a conversation is a route change, so its payload is fetched at the
  // worst moment — after the click. Pointer-enter is tens to hundreds of
  // milliseconds earlier, which covers most of the round trip.
  const showHiddenChats = useUIStore((s) => s.showHiddenChats);
  const setShowHiddenChats = useUIStore((s) => s.setShowHiddenChats);
  const setChatHidden = useChatsStore((s) => s.setChatHidden);
  const groups = useGroupsStore((s) => s.groups);
  const activeGroupId = useGroupsStore((s) => s.activeGroupId);
  const setActiveGroup = useGroupsStore((s) => s.setActiveGroup);
  const unreadByGroup = useGroupsStore((s) => s.unreadByGroup);

  const [activeTab, setActiveTab] = useState<'chats' | 'groups'>('chats');
  // The tab underline travels to whichever tab you picked, so the motion
  // shows where the selection went rather than just recolouring.
  const chatsTabRef = useRef<HTMLButtonElement>(null);
  const groupsTabRef = useRef<HTMLButtonElement>(null);
  const [tabIndicator, setTabIndicator] = useState<{ left: number; width: number } | null>(null);

  // "New chat" opens a small popover anchored to the + button (not a dialog).
  const addBtnRef = useRef<HTMLButtonElement>(null);
  const [addOpen, setAddOpen] = useState(false);

  useEffect(() => {
    // A second, hidden copy of this panel is mounted for the mobile shell; it
    // measures 0 until it becomes visible. Skip zero-width reads and re-measure
    // via ResizeObserver so the underline is correct whenever the panel shows.
    const measure = () => {
      const el = activeTab === 'chats' ? chatsTabRef.current : groupsTabRef.current;
      if (el && el.offsetWidth > 0) {
        setTabIndicator({ left: el.offsetLeft, width: el.offsetWidth });
      }
    };

    measure();

    const observer = new ResizeObserver(measure);
    if (chatsTabRef.current) observer.observe(chatsTabRef.current);
    if (groupsTabRef.current) observer.observe(groupsTabRef.current);
    window.addEventListener('resize', measure);

    return () => {
      observer.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, [activeTab]);
  const [hiddenChatsEnabled, setHiddenChatsEnabled] = useState(false);
  const [hiddenChatPinHash, setHiddenChatPinHash] = useState<string | null>(null);
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [hiddenPin, setHiddenPin] = useState('');
  const [hiddenPinError, setHiddenPinError] = useState('');

  const reloadSettings = useCallback(async () => {
    try {
      const mk = vaultHasMasterKey() ? vaultGetMasterKey() : undefined;
      const settings = await loadSettings(mk);
      setHiddenChatsEnabled(!!settings.hiddenChatsEnabled);
      setHiddenChatPinHash(settings.hiddenChatPinHash || null);
      if (!settings.hiddenChatsEnabled) {
        setShowHiddenChats(false);
      }
    } catch {
      // ignore
    }
  }, [setShowHiddenChats]);

  // Initial load
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void reloadSettings();
  }, [reloadSettings]);

  // Re-sync settings when the user returns to this view after visiting Settings.
  // MessengerShell stays mounted during route navigation, so mount-only load is
  // insufficient — we listen for window focus and document visibility changes.
  useEffect(() => {
    const handleFocus = () => void reloadSettings();
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        void reloadSettings();
      }
    };

    window.addEventListener('focus', handleFocus);
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      window.removeEventListener('focus', handleFocus);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [reloadSettings]);

  const openHiddenUnlock = () => {
    setHiddenPin('');
    setHiddenPinError('');
    setShowUnlockModal(true);
  };

  const toggleHiddenView = () => {
    if (!hiddenChatsEnabled) return;
    if (showHiddenChats) {
      setShowHiddenChats(false);
      return;
    }
    if (hiddenChatPinHash) {
      openHiddenUnlock();
      return;
    }
    setShowHiddenChats(true);
  };

  const [hiddenAttempts, setHiddenAttempts] = useState(0);
  const [hiddenLockUntil, setHiddenLockUntil] = useState(0);

  const unlockHiddenChats = async () => {
    if (!hiddenChatPinHash) {
      setShowHiddenChats(true);
      setShowUnlockModal(false);
      return;
    }
    if (hiddenLockUntil > Date.now()) {
      const secs = Math.ceil((hiddenLockUntil - Date.now()) / 1000);
      setHiddenPinError(`Too many attempts. Try again in ${secs}s`);
      return;
    }
    if (hiddenPin.trim().length < MIN_PIN_LENGTH) {
      setHiddenPinError('PIN must be at least 4 characters');
      return;
    }
    const ok = await verifyHiddenChatPin(hiddenPin, hiddenChatPinHash);
    if (!ok) {
      const next = hiddenAttempts + 1;
      setHiddenAttempts(next);
      setHiddenPin('');
      if (next >= 5) {
        const lockMs = Math.min(30000 * Math.pow(2, next - 5), 300000);
        setHiddenLockUntil(Date.now() + lockMs);
      }
      setHiddenPinError(t("chatList.errorHiddenPin"));
      return;
    }
    setHiddenAttempts(0);
    // Transparent migration: re-hash legacy PINs with stronger iterations.
    // Best-effort, and only with the master key — never persist the hash plaintext.
    if (isLegacyHiddenPinHash(hiddenChatPinHash)) {
      try {
        const masterKey = vaultGetMasterKey();
        const newHash = await hashHiddenChatPin(hiddenPin);
        const settings = await loadSettings(masterKey);
        settings.hiddenChatPinHash = newHash;
        await saveSettings(settings, masterKey);
      } catch {
        // Migration is best-effort; never block unlock or fall back to plaintext.
      }
    }
    setShowHiddenChats(true);
    setShowUnlockModal(false);
    setHiddenPin('');
    setHiddenPinError('');
  };

  const toggleChatHidden = useCallback((chatId: string) => {
    const target = chats.find((c) => c.id === chatId);
    if (!target) return;

    if (!hiddenChatsEnabled) return;
    setChatHidden(chatId, !target.isHidden);
  }, [chats, hiddenChatsEnabled, setChatHidden]);

  const [debouncedQuery, setDebouncedQuery] = useState('');
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    const trimmed = searchQuery.trim().toLowerCase();
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => setDebouncedQuery(trimmed), 250);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [searchQuery]);

  const modeScopedChats = useMemo(() =>
    chats.filter((chat) => {
      if (!hiddenChatsEnabled) return true;
      return showHiddenChats ? chat.isHidden : !chat.isHidden;
    }),
    [chats, hiddenChatsEnabled, showHiddenChats],
  );

  const query = debouncedQuery;

  // Indexed once per contacts change rather than scanned per chat: the filter
  // below runs on every keystroke, and contacts.find() inside it made that
  // O(chats × contacts) each time.
  const contactById = useMemo(() => {
    const map = new Map<string, Contact>();
    for (const c of contacts) map.set(c.id, c);
    return map;
  }, [contacts]);

  const filtered = useMemo(() =>
    modeScopedChats.filter((chat) => {
      const contact = contactById.get(chat.contactId);
      if (!contact) return false;
      if (!query) return true;
      if (contact.username.toLowerCase().includes(query)) return true;
      return chat.messages.some((m) => m.content.toLowerCase().includes(query));
    }),
    [modeScopedChats, contactById, query],
  );

  const filteredGroups = useMemo(() =>
    groups.filter((g) => {
      if (!query) return true;
      return g.name.toLowerCase().includes(query);
    }),
    [groups, query],
  );

  const handleSelectGroup = (groupId: string) => {
    setActiveGroup(groupId);
    // Clear individual chat selection when selecting a group
    onSelectChat('');
  };

  return (
    <div className="h-full min-h-0 overflow-hidden flex flex-col">
      <div className="px-4 sm:px-5 pt-5 pb-3 border-b border-[var(--border)]/70 flex-shrink-0">
        {/* Search + actions */}
        <div className="flex items-center gap-2">
          <div className="relative flex-1 min-w-0">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="1.8"
                  d="M21 21l-4.3-4.3m1.8-5.2a7 7 0 11-14 0 7 7 0 0114 0z"
                />
              </svg>
            </span>
            <input
              id={`${fieldId}-search`}
              name="chat-search"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder={activeTab === 'chats' ? t("chatList.searchChats") : t("chatList.searchGroups")}
              disabled={activeTab === 'chats' ? modeScopedChats.length === 0 : groups.length === 0}
              aria-label={activeTab === 'chats' ? t("chatList.searchChatsAria") : t("chatList.searchGroupsAria")}
              className="w-full bg-transparent border-0 border-b border-[var(--border)] pl-8 pr-2 py-2 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--text-secondary)] transition-colors disabled:opacity-50"
            />
          </div>

          {/* Settings shortcut — mobile only (desktop has LeftRail) */}
          <button
            type="button"
            onClick={() => router.push('/settings')}
            className="md:hidden w-9 h-9 rounded-full inline-flex items-center justify-center text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-alt)] transition-colors flex-shrink-0"
            aria-label={t("chatList.settings")}
            title={t("chatList.settings")}
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <circle cx="12" cy="12" r="3" strokeWidth="1.8" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
            </svg>
          </button>

          {activeTab === 'chats' && hiddenChatsEnabled ? (
            <button
              type="button"
              onClick={toggleHiddenView}
              className="w-9 h-9 rounded-full inline-flex items-center justify-center text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-alt)] transition-colors flex-shrink-0"
              aria-label={showHiddenChats ? t("chatList.backToMain") : t("chatList.openHidden")}
              title={showHiddenChats ? t("chatList.mainChats") : t("chatList.hiddenChats")}
            >
              {showHiddenChats ? (
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M15 19l-7-7 7-7" />
                </svg>
              ) : (
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 11c1.657 0 3-1.567 3-3.5S13.657 4 12 4 9 5.567 9 7.5 10.343 11 12 11z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M6 11v7a1 1 0 001 1h10a1 1 0 001-1v-7" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M9 11V8.5C9 6.567 10.343 5 12 5s3 1.567 3 3.5V11" />
                </svg>
              )}
            </button>
          ) : null}

          <button
            ref={addBtnRef}
            type="button"
            onClick={() => {
              if (activeTab === 'chats') {
                if (!addOpen) onClearAddContactError?.();
                setAddOpen((o) => !o);
              } else {
                onNewGroup?.();
              }
            }}
            className="w-9 h-9 rounded-full inline-flex items-center justify-center text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-alt)] transition-colors flex-shrink-0"
            aria-label={activeTab === 'chats' ? t("chatList.newChat") : t("chatList.newGroup")}
            title={activeTab === 'chats' ? t("chatList.newChat") : t("chatList.newGroup")}
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 5v14" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M5 12h14" />
            </svg>
          </button>
        </div>

        {/* Tabs — the underline travels to the tab you picked */}
        <div className="relative mt-4 text-sm">
          <span
            aria-hidden="true"
            className={`absolute bottom-0 left-0 h-[2px] bg-[var(--text-primary)] ${tabIndicator ? '[transition:transform_0.25s_cubic-bezier(0.22,1,0.36,1),width_0.25s_cubic-bezier(0.22,1,0.36,1)] motion-reduce:transition-none' : 'opacity-0'}`}
            style={
              tabIndicator
                ? { width: `${tabIndicator.width}px`, transform: `translateX(${tabIndicator.left}px)` }
                : undefined
            }
          />
          <div className="flex items-center gap-5">
          <button
            ref={chatsTabRef}
            type="button"
            onClick={() => { setActiveTab('chats'); setActiveGroup(null); }}
            className={`pb-2 transition-colors ${activeTab === 'chats' ? 'text-[var(--text-primary)] font-semibold' : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'}`}
          >
            {t("chatList.tabChats")}
          </button>
          <button
            ref={groupsTabRef}
            type="button"
            onClick={() => setActiveTab('groups')}
            className={`pb-2 transition-colors ${activeTab === 'groups' ? 'text-[var(--text-primary)] font-semibold' : 'text-[var(--text-muted)] hover:text-[var(--text-secondary)]'}`}
          >
            {t("chatList.tabGroups")}
          </button>
          {activeTab === 'chats' && hiddenChatsEnabled && showHiddenChats ? (
            <span className="ml-auto text-caption text-[var(--text-muted)]">{t("hidden.title")}</span>
          ) : null}
          </div>
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto">
        {activeTab === 'chats' && filtered.length === 0 && modeScopedChats.length === 0 ? (
          <div className="h-full flex items-center justify-center text-center px-6">
            <p className="text-sm text-[var(--text-muted)]">{t("chatList.noChats")}</p>
          </div>
        ) : activeTab === 'groups' && filteredGroups.length === 0 && groups.length === 0 ? (
          <div className="h-full flex items-center justify-center text-center px-6">
            <p className="text-sm text-[var(--text-muted)]">{t("chatList.noGroups")}</p>
          </div>
        ) : (
        <div className="py-1">
          {activeTab === 'chats' ? (
            filtered.map((chat) => {
              const contact = contactById.get(chat.contactId);
              if (!contact) return null;
              return (
                <ChatRow
                  key={chat.id}
                  chat={chat}
                  contact={contact}
                  selected={selectedChatId === chat.id}
                  onClick={() => onSelectChat(chat.id)}
                  showHiddenControls={hiddenChatsEnabled}
                  onToggleHidden={toggleChatHidden}
                  searchHighlight={query || undefined}
                  avatarUrl={avatarMap?.[contact.id]}
                />
              );
            })
          ) : (
            filteredGroups.map((group) => (
              <GroupRow
                key={group.id}
                group={group}
                selected={activeGroupId === group.id}
                onClick={() => handleSelectGroup(group.id)}
                unread={unreadByGroup[group.id] ?? 0}
              />
            ))
          )}
        </div>
        )}
      </div>

      <Modal
        isOpen={showUnlockModal}
        onClose={() => setShowUnlockModal(false)}
        title={t("chatList.hiddenChats")}
      >
        <div className="space-y-4">
          <p className="text-xs text-[var(--text-secondary)]">
            {t("hidden.prompt")}
          </p>
          <Input
            type="password"
            value={hiddenPin}
            onChange={(e) => {
              setHiddenPin(e.target.value);
              if (hiddenPinError) setHiddenPinError('');
            }}
            placeholder={t("chatList.hiddenPinPlaceholder")}
            aria-label={t("chatList.hiddenPinPlaceholder")}
            autoFocus
            error={hiddenPinError || undefined}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                void unlockHiddenChats();
              }
            }}
          />
          <Button fullWidth onClick={() => void unlockHiddenChats()}>
            {t("common.unlock")}
          </Button>
        </div>
      </Modal>

      <AddContactPopover
        open={addOpen}
        onClose={() => setAddOpen(false)}
        anchorRef={addBtnRef}
        onSubmit={onAddContact}
        error={addContactError}
        loading={addContactLoading}
      />
    </div>
  );
}
