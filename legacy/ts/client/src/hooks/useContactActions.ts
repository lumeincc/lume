// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Shared hook: add-contact + open-chat-for-contact logic.
 *
 * Used by the chats page and by the contacts rail beside it. It used to be
 * shared with a separate `/chat/[id]` page, which is why it exists at all;
 * that page is now a redirect and the conversation renders in place.
 */

import { useState, useCallback } from "react";
import { v4 as uuidv4 } from "uuid";
import {
  useAuthStore,
  useContactsStore,
  useChatsStore,
  useGroupsStore,
} from "@/stores";
import { authApi } from "@/lib/api";
import { saveContacts, type Contact } from "@/crypto/storage";
import { vaultGetMasterKey, vaultHasKeys } from "@/crypto/keyVault";

export function useContactActions() {
  const username = useAuthStore((s) => s.username);
  const addContact = useContactsStore((s) => s.addContact);
  const addChat = useChatsStore((s) => s.addChat);
  const setActiveChat = useChatsStore((s) => s.setActiveChat);
  const setActiveGroup = useGroupsStore((s) => s.setActiveGroup);

  const [showAddContact, setShowAddContact] = useState(false);
  const [addContactError, setAddContactError] = useState("");
  const [addContactLoading, setAddContactLoading] = useState(false);

  const openChatForContact = useCallback(
    (contactId: string) => {
      const existing = useChatsStore
        .getState()
        .chats.find((c) => c.contactId === contactId);
      let chatId = existing?.id;
      if (!chatId) {
        chatId = uuidv4();
        addChat({
          id: chatId,
          contactId,
          messages: [],
          unreadCount: 0,
          isHidden: false,
        });
      }
      // Selecting the chat *is* opening it — there is no navigation any more.
      // The group has to be cleared here too: the chats page shows a group in
      // preference to a chat, so without this, opening a contact from the rail
      // while a group is on screen would change nothing visible.
      setActiveGroup(null);
      setActiveChat(chatId);
    },
    [addChat, setActiveChat, setActiveGroup],
  );

  const handleAddContact = useCallback(async (input: string) => {
    setAddContactError("");
    setAddContactLoading(true);

    try {
      const normalized = input.trim();
      if (!vaultHasKeys()) {
        setAddContactError("Not authenticated");
        return false;
      }
      const { data, error } = await authApi.getUser(normalized);
      if (error || !data) {
        setAddContactError("User not found");
        return false;
      }

      if (data.username === username) {
        setAddContactError("Cannot add yourself");
        return false;
      }

      if (
        useContactsStore
          .getState()
          .contacts.some((c) => c.username === data.username)
      ) {
        setAddContactError("Contact already added");
        return false;
      }

      const newContact: Contact = {
        id: data.id,
        username: data.username,
        publicKey: data.identityKey,
        exchangeKey:
          data.exchangeIdentityKey || data.exchangeKey || data.signedPrekey,
        addedAt: Date.now(),
      };

      addContact(newContact);
      const updatedContacts = useContactsStore.getState().contacts;

      try {
        const mk = vaultGetMasterKey();
        await saveContacts(updatedContacts, mk);
      } catch {
        // Vault may not have master key yet — contacts still added in-memory
      }

      setShowAddContact(false);

      openChatForContact(data.id);
      return true;
    } catch (e) {
      if (process.env.NODE_ENV !== "production")
        console.error("Add contact error:", e);
      setAddContactError("Error adding contact");
      return false;
    } finally {
      setAddContactLoading(false);
    }
  }, [
    username,
    addContact,
    openChatForContact,
  ]);

  const resetAddContact = useCallback(() => {
    setShowAddContact(false);
    setAddContactError("");
  }, []);

  return {
    showAddContact,
    setShowAddContact,
    addContactError,
    addContactLoading,
    handleAddContact,
    openChatForContact,
    resetAddContact,
  };
}
