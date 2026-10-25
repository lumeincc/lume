// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

'use client';

import React, { useState, useEffect } from 'react';
import { t } from "@/lib/i18n";
import { usePathname, useRouter } from 'next/navigation';
import { usePrefetchRoutes } from '@/hooks/useRoutePrefetch';

/** Fixed rail destinations. Module-scoped so its identity is stable. */
const RAIL_ROUTES = ['/chats', '/settings'] as const;
import { useAuthStore, useChatsStore, useUIStore } from '@/stores';
import { Avatar } from '@/components/ui';
import OwnProfileModal from '@/components/modals/OwnProfileModal';
import { profileApi, filesApi } from '@/lib/api';
import { downloadAndCacheAvatar, getCachedAvatarUrl } from '@/lib/avatarCache';
import { vaultHasKeys } from '@/crypto/keyVault';

const ICON_CLASS = 'w-[22px] h-[22px] flex-shrink-0';

const MessengerIcon = (
  <svg className={ICON_CLASS} viewBox="0 0 24 24" fill="none" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z" />
  </svg>
);

const SettingsIcon = (
  <svg className={ICON_CLASS} viewBox="0 0 24 24" fill="none" stroke="currentColor">
    <circle cx="12" cy="12" r="3" strokeWidth="1.8" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
  </svg>
);

const FilesIcon = (
  <svg className={ICON_CLASS} viewBox="0 0 24 24" fill="none" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z" />
  </svg>
);

const BackupIcon = (
  <svg className={ICON_CLASS} viewBox="0 0 24 24" fill="none" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M7 10l5 5 5-5" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 15V3" />
  </svg>
);

const PanicIcon = (
  <svg className={ICON_CLASS} viewBox="0 0 24 24" fill="none" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 9v3" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M12 16h.01" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.8" d="M10.3 3.4a2 2 0 013.4 0l8.2 14.2A2 2 0 0120.2 21H3.8a2 2 0 01-1.7-3.4l8.2-14.2z" />
  </svg>
);

function RailIcon({
  active,
  label,
  icon,
  onClick,
  disabled,
}: {
  active?: boolean;
  label: string;
  icon: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      aria-label={label}
      title={label}
      aria-current={active ? 'page' : undefined}
      className={`
        w-11 h-11 rounded-[14px] inline-flex items-center justify-center transition-colors
        ${disabled ? 'text-[var(--text-muted)] opacity-40 cursor-not-allowed' : ''}
        ${
          active
            ? 'bg-[var(--surface-alt)] text-[var(--text-primary)]'
            : disabled
              ? ''
              : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-alt)]'
        }
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]
      `}
    >
      {icon}
    </button>
  );
}

function PanelRow({
  active,
  label,
  icon,
  onClick,
  disabled,
}: {
  active?: boolean;
  label: string;
  icon: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      aria-current={active ? 'page' : undefined}
      className={`
        flex items-center gap-3 w-full px-3 py-3 rounded-[14px] text-[15px] transition-colors
        ${
          active
            ? 'bg-[var(--surface-alt)] text-[var(--text-primary)] font-semibold'
            : disabled
              ? 'text-[var(--text-muted)] opacity-40 cursor-not-allowed'
              : 'text-[var(--text-secondary)] hover:bg-[var(--surface-alt)] hover:text-[var(--text-primary)]'
        }
        focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]
      `}
    >
      {icon}
      {label}
    </button>
  );
}

export default function LeftRail({
  onPanic,
  onOpenBackup,
  variant = 'rail',
}: {
  onPanic?: () => void;
  onOpenBackup?: () => void;
  /** `rail` = slim desktop icon strip · `panel` = full-width mobile profile panel */
  variant?: 'rail' | 'panel';
}) {
  const router = useRouter();
  // The rail is on every screen and its destinations never change, so warm both
  // while the browser is idle rather than at the moment of the click.
  usePrefetchRoutes(RAIL_ROUTES);
  const pathname = usePathname();
  const userId = useAuthStore((s) => s.userId);
  const username = useAuthStore((s) => s.username);
  const discoverable = useAuthStore((s) => s.discoverable);
  const hasKeys = useAuthStore((s) => s.hasIdentityKeys);
  const wsStatus = useUIStore((s) => s.wsStatus);
  const totalUnread = useChatsStore((s) => s.chats.reduce((sum, c) => sum + (c.unreadCount || 0), 0));

  const [ownAvatarUrl, setOwnAvatarUrl] = useState<string | null>(null);
  const [showOwnProfile, setShowOwnProfile] = useState(false);

  // Load own avatar
  useEffect(() => {
    if (!userId || !vaultHasKeys()) return;
    let cancelled = false;

    (async () => {
      try {
        const res = await profileApi.get(userId);
        if (cancelled || !res.data?.avatarFileId) return;

        const fid = res.data.avatarFileId;
        const cached = getCachedAvatarUrl(fid);
        if (cached) {
          setOwnAvatarUrl(cached);
          return;
        }

        const url = await downloadAndCacheAvatar(fid, async () => {
          const r = await filesApi.download(fid);
          if (!r.data) return null;
          return { data: r.data.data, mimeHint: r.data.mimeHint };
        });
        if (!cancelled) setOwnAvatarUrl(url);
      } catch {
        // Best effort
      }
    })();

    return () => { cancelled = true; };
  }, [userId, hasKeys]);

  const messengerActive = pathname.startsWith('/chat') || pathname.startsWith('/chats');
  const settingsActive = pathname === '/settings';
  const online = wsStatus === 'connected';
  const statusDotColor = online
    ? 'bg-[var(--hl)]'
    : wsStatus === 'connecting'
      ? 'bg-[var(--text-muted)]'
      : 'bg-[var(--text-muted)] opacity-50';
  const statusTitle = online ? t("rail.online") : wsStatus === 'connecting' ? t("rail.connecting") : t("rail.offline");
  const displayName = !discoverable ? t("rail.anonymous") : username ? `@${username}` : t("rail.guest");

  const unreadBadge =
    totalUnread > 0 ? (
      <span className="absolute -right-1 -top-1 min-w-[18px] h-[18px] px-1 rounded-full bg-[var(--accent)] text-[var(--accent-contrast)] text-micro font-semibold flex items-center justify-center border border-[var(--border)]">
        {totalUnread > 99 ? '99+' : totalUnread}
      </span>
    ) : null;

  // ── Mobile: full-width profile panel ──────────────────────────────────────
  if (variant === 'panel') {
    return (
      <div className="h-full min-h-0 overflow-y-auto flex flex-col items-center px-6 py-10">
        <button
          type="button"
          onClick={() => setShowOwnProfile(true)}
          className="relative rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
          aria-label={t("rail.profile")}
        >
          <Avatar src={ownAvatarUrl} username={username ?? 'U'} size="xl" />
          <span
            className={`absolute right-1.5 bottom-1.5 w-4 h-4 rounded-full ring-2 ring-[var(--background)] ${statusDotColor}`}
            aria-hidden="true"
          />
          {unreadBadge}
        </button>

        <p className="mt-4 text-[17px] font-semibold text-[var(--text-primary)]">{displayName}</p>
        <p className="mt-1 text-xs text-[var(--text-muted)]">{statusTitle}</p>

        <nav className="mt-9 w-full max-w-xs flex flex-col gap-1">
          <PanelRow active={messengerActive} label={t("rail.messenger")} icon={MessengerIcon} onClick={() => router.push('/chats')} />
          <PanelRow active={settingsActive} label={t("rail.settings")} icon={SettingsIcon} onClick={() => router.push('/settings')} />
          <PanelRow disabled label={t("rail.files")} icon={FilesIcon} />
          <PanelRow label={t("rail.backup")} icon={BackupIcon} onClick={onOpenBackup} />
        </nav>

        <button
          type="button"
          onClick={onPanic}
          className="mt-auto pt-8 flex items-center gap-2 text-body text-red-500 hover:text-red-400 transition-colors"
        >
          {PanicIcon}
          Wipe local data
        </button>

        <OwnProfileModal
          isOpen={showOwnProfile}
          onClose={() => setShowOwnProfile(false)}
          username={username}
          discoverable={discoverable}
          avatarUrl={ownAvatarUrl}
          online={online}
          onEditProfile={() => { setShowOwnProfile(false); router.push('/settings'); }}
        />
      </div>
    );
  }

  // ── Desktop: slim icon rail ───────────────────────────────────────────────
  return (
    <div className="h-full min-h-0 overflow-hidden flex flex-col items-center py-5">
      {/* Avatar → own profile · status dot · unread badge */}
      <button
        type="button"
        onClick={() => setShowOwnProfile(true)}
        className="relative rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]"
        aria-label={t("rail.profile")}
        title={`Profile · ${statusTitle}`}
      >
        <Avatar src={ownAvatarUrl} username={username ?? 'U'} size="lg" />
        <span
          className={`absolute right-0 bottom-0 w-3.5 h-3.5 rounded-full ring-2 ring-[var(--background)] ${statusDotColor}`}
          aria-hidden="true"
        />
        {unreadBadge}
      </button>

      {/* Navigation */}
      <div className="mt-7 flex flex-col items-center gap-2">
        <RailIcon active={messengerActive} label={t("rail.messenger")} icon={MessengerIcon} onClick={() => router.push('/chats')} />
        <RailIcon active={settingsActive} label={t("rail.settings")} icon={SettingsIcon} onClick={() => router.push('/settings')} />
        <RailIcon disabled label={t("rail.filesComingSoon")} icon={FilesIcon} />
        <RailIcon label={t("rail.backup")} icon={BackupIcon} onClick={onOpenBackup} />
      </div>

      {/* Panic — wipe local data */}
      <button
        type="button"
        onClick={onPanic}
        className="mt-auto w-11 h-11 inline-flex items-center justify-center rounded-[14px] text-red-500 hover:bg-red-500/10 transition-colors"
        aria-label={t("rail.wipe")}
        title={t("rail.wipe")}
      >
        {PanicIcon}
      </button>

      <OwnProfileModal
        isOpen={showOwnProfile}
        onClose={() => setShowOwnProfile(false)}
        username={username}
        discoverable={discoverable}
        avatarUrl={ownAvatarUrl}
        online={online}
        onEditProfile={() => { setShowOwnProfile(false); router.push('/settings'); }}
      />
    </div>
  );
}
