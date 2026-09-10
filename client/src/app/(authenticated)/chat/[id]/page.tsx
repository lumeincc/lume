// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Deep link into one conversation.
 *
 * The conversation itself is no longer a page — it is `ChatView`, rendered
 * inside `/chats` as ordinary state, so opening a chat does not rebuild the
 * dashboard around it. This route stays because the URLs exist: bookmarks,
 * notification click-throughs and anything already linking to `/chat/<id>`
 * still have to land somewhere sensible.
 *
 * So it does one thing — select the chat and hand over to `/chats`.
 */

"use client";

import { use, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useChatsStore } from "@/stores";
import { useHydrated } from "@/hooks/useMessengerSync";
import { MessagesSkeleton } from "@/components/ui";

const UUID =
  /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/;

interface ChatPageProps {
  params: Promise<{ id: string }>;
}

export default function ChatPage({ params }: ChatPageProps) {
  const { id } = use(params);
  const router = useRouter();
  const hydrated = useHydrated();
  const setActiveChat = useChatsStore((s) => s.setActiveChat);

  useEffect(() => {
    // Wait for the stores to load: selecting a chat before the chat list exists
    // would be overwritten by hydration, and the reader would land on an empty
    // dashboard instead of the conversation they asked for.
    if (!hydrated) return;
    // The id comes from the URL, so it is checked before it reaches the store.
    // An unknown-but-well-formed id is left to `ChatView`, which already has a
    // "chat not found" state; a malformed one is not worth selecting at all.
    setActiveChat(UUID.test(id) ? id : null);
    router.replace("/chats");
  }, [hydrated, id, setActiveChat, router]);

  return (
    <div aria-busy="true" className="h-full overflow-hidden flex flex-col">
      <MessagesSkeleton />
    </div>
  );
}
