// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Messenger: chats list / dashboard shell (desktop)
 * Mobile shows only the chats list.
 */

"use client";

import { useState, useEffect } from "react";
import { t } from "@/lib/i18n";
import { useRouter } from "next/navigation";
import MessengerShell from "@/components/messenger/MessengerShell";
import MobileSwipeShell from "@/components/messenger/MobileSwipeShell";
import LeftRail from "@/components/messenger/LeftRail";
import ChatListPanel from "@/components/messenger/ChatListPanel";
import RightRail from "@/components/messenger/RightRail";
import { ChatListSkeleton } from "@/components/ui";
import GroupView from "@/components/chat/GroupView";
import ChatView from "@/components/chat/ChatView";
import dynamic from "next/dynamic";

const BackupModal = dynamic(
  () => import("@/components/modals").then((m) => ({ default: m.BackupModal })),
  { ssr: false },
);
const CreateGroupModal = dynamic(
  () =>
    import("@/components/modals").then((m) => ({
      default: m.CreateGroupModal,
    })),
  { ssr: false },
);
const PanicModal = dynamic(
  () => import("@/components/modals").then((m) => ({ default: m.PanicModal })),
  { ssr: false },
);
import { useHydrated } from "@/hooks/useMessengerSync";
import { useContactActions } from "@/hooks/useContactActions";
import { usePanic } from "@/hooks/usePanic";
import { groupsApi } from "@/lib/api";
import {
  useAuthStore,
  useContactsStore,
  useChatsStore,
  useGroupsStore,
} from "@/stores";
import { useContactAvatars } from "@/hooks/useContactAvatars";

export default function ChatsPage() {
  const router = useRouter();

  const hydrated = useHydrated();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const hasIdentityKeys = useAuthStore((s) => s.hasIdentityKeys);
  const contacts = useContactsStore((s) => s.contacts);
  const chats = useChatsStore((s) => s.chats);
  const activeChatId = useChatsStore((s) => s.activeChatId);
  const setActiveChat = useChatsStore((s) => s.setActiveChat);
  const { groups, activeGroupId, setGroups, setActiveGroup } = useGroupsStore();
  const avatarMap = useContactAvatars(contacts);

  const {
    addContactError,
    addContactLoading,
    handleAddContact,
    openChatForContact,
    resetAddContact,
  } = useContactActions();

  const { isPanicMode, showPanicConfirm, setShowPanicConfirm, executePanic } =
    usePanic();

  const [searchQuery, setSearchQuery] = useState("");
  const [showBackupModal, setShowBackupModal] = useState(false);
  const [showCreateGroup, setShowCreateGroup] = useState(false);

  // Auth guard — redirect in useEffect to avoid render-phase side effects.
  useEffect(() => {
    if (hydrated && !isAuthenticated) {
      router.replace("/");
    }
  }, [hydrated, isAuthenticated, router]);

  // Fetch groups on mount / when identity keys become available
  useEffect(() => {
    if (!hasIdentityKeys) return;
    void (async () => {
      const result = await groupsApi.list();
      if (result.data?.groups) {
        setGroups(result.data.groups);
      }
    })();
  }, [hasIdentityKeys, setGroups]);

  if (!hydrated) {
    return (
      <MessengerShell
        leftRail={<div className="h-full" />}
        chatList={<ChatListSkeleton />}
        main={
          <div
            aria-busy="true"
            className="h-full flex items-center justify-center"
          >
            <div className="w-8 h-8 border-2 mono-spinner rounded-full animate-spin" />
          </div>
        }
      />
    );
  }

  if (!isAuthenticated) {
    return null;
  }

  // Opening a chat is a state change, not a navigation. It used to push
  // `/chat/[id]`, a route whose page re-declared this entire dashboard around
  // the conversation — so every panel on screen, including the list just
  // clicked in, was torn down and rebuilt to swap the middle column.
  const handleSelectChat = (chatId: string) => {
    if (!chatId) {
      // Called when switching to groups tab — clear individual chat selection
      setActiveChat(null);
      return;
    }
    setActiveGroup(null);
    setActiveChat(chatId);
  };

  const activeGroup = activeGroupId
    ? (groups.find((g) => g.id === activeGroupId) ?? null)
    : null;

  if (isPanicMode) {
    return (
      <div className="h-full flex items-center justify-center">
        <p className="text-[var(--text-secondary)] text-sm">
          No messages
        </p>
      </div>
    );
  }

  const emptyMain = (
    <div className="h-full min-h-0 overflow-hidden">
      <div className="h-full flex items-center justify-center px-8 text-center animate-settle">
        <p className="text-sm text-[var(--text-muted)]">{t("chat.selectAChat")}</p>
      </div>
    </div>
  );

  const closeChat = () => setActiveChat(null);

  const mainContent = activeGroup ? (
    <GroupView group={activeGroup} />
  ) : activeChatId ? (
    <ChatView chatId={activeChatId} onClose={closeChat} />
  ) : (
    emptyMain
  );

  const chatListNode = (
    <ChatListPanel
      chats={chats}
      contacts={contacts}
      selectedChatId={activeChatId}
      searchQuery={searchQuery}
      onSearchChange={setSearchQuery}
      onSelectChat={handleSelectChat}
      onAddContact={handleAddContact}
      addContactError={addContactError}
      addContactLoading={addContactLoading}
      onClearAddContactError={resetAddContact}
      onNewGroup={() => setShowCreateGroup(true)}
      avatarMap={avatarMap}
    />
  );

  const mobileProfileNode = (
    <LeftRail
      variant="panel"
      onPanic={() => setShowPanicConfirm(true)}
      onOpenBackup={() => setShowBackupModal(true)}
    />
  );

  const leftRailNode = (
    <LeftRail
      onPanic={() => setShowPanicConfirm(true)}
      onOpenBackup={() => setShowBackupModal(true)}
    />
  );

  return (
    <div className="h-[100dvh] w-full overflow-hidden">
      {/* Mobile: an open conversation takes the whole screen; otherwise the
          swipeable Profile + Messages panels. */}
      <div className="md:hidden h-full min-h-0">
        {activeGroup ? (
          <GroupView group={activeGroup} />
        ) : activeChatId ? (
          <ChatView chatId={activeChatId} onClose={closeChat} />
        ) : (
          <MobileSwipeShell
            profilePanel={mobileProfileNode}
            chatListPanel={chatListNode}
          />
        )}
      </div>

      {/* Desktop: 4-column dashboard like the reference */}
      <div className="hidden md:block h-full min-h-0">
        <MessengerShell
          leftRail={leftRailNode}
          chatList={chatListNode}
          main={mainContent}
          rightRail={
            contacts.length > 0 ? (
              <RightRail
                contacts={contacts}
                chats={chats}
                activeChatId={activeChatId}
                onOpenContact={openChatForContact}
                avatarMap={avatarMap}
              />
            ) : undefined
          }
        />
      </div>


      <PanicModal
        isOpen={showPanicConfirm}
        onClose={() => setShowPanicConfirm(false)}
        onConfirm={executePanic}
      />

      <CreateGroupModal
        isOpen={showCreateGroup}
        onClose={() => setShowCreateGroup(false)}
      />

      <BackupModal
        isOpen={showBackupModal}
        onClose={() => setShowBackupModal(false)}
      />
    </div>
  );
}
