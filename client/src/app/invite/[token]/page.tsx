// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Invite resolution page.
 * Resolves an invite token and allows adding the user as a contact.
 */

"use client";

import { useState, useEffect, useCallback } from "react";
import { t } from "@/lib/i18n";
import { useParams, useRouter } from "next/navigation";
import { v4 as uuidv4 } from "uuid";
import { inviteApi } from "@/lib/api";
import { saveContacts, type Contact } from "@/crypto/storage";
import {
  useAuthStore,
  useContactsStore,
  useChatsStore,
} from "@/stores";
import { vaultHasKeys, vaultGetMasterKey } from "@/crypto/keyVault";

type InviteState =
  | { status: "loading" }
  | { status: "resolved"; user: ResolvedUser }
  | { status: "error"; message: string }
  | { status: "added"; chatId: string };

interface ResolvedUser {
  id: string;
  username: string;
  identityKey: string;
  exchangeKey: string;
  signedPrekey: string;
  signedPrekeySignature: string;
}

export default function InvitePage() {
  const params = useParams();
  const router = useRouter();
  const token = params.token as string;

  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const hasIdentityKeys = useAuthStore((s) => s.hasIdentityKeys);
  const username = useAuthStore((s) => s.username);

  const [state, setState] = useState<InviteState>({ status: "loading" });
  const [adding, setAdding] = useState(false);

  // Resolve the invite token
  useEffect(() => {
    if (!isAuthenticated || !vaultHasKeys()) {
      // Store token for after login
      sessionStorage.setItem("lume:pending-invite", token);
      router.replace("/");
      return;
    }

    let cancelled = false;

    async function resolve() {
      const result = await inviteApi.resolveToken(token);
      if (cancelled) return;

      if (result.error) {
        setState({ status: "error", message: result.error });
        return;
      }

      if (!result.data) {
        setState({ status: "error", message: t("invite.errorInvalid") });
        return;
      }

      setState({
        status: "resolved",
        user: {
          id: result.data.id,
          username: result.data.username,
          identityKey: result.data.identityKey,
          exchangeKey:
            result.data.exchangeIdentityKey ||
            result.data.exchangeKey ||
            result.data.signedPrekey,
          signedPrekey: result.data.signedPrekey,
          signedPrekeySignature: result.data.signedPrekeySignature,
        },
      });
    }

    void resolve();
    return () => {
      cancelled = true;
    };
  }, [token, isAuthenticated, hasIdentityKeys, router]);

  const handleAddContact = useCallback(async () => {
    if (state.status !== "resolved") return;
    setAdding(true);

    try {
      const { user } = state;

      if (user.username === username) {
        setState({ status: "error", message: t("invite.errorSelf") });
        return;
      }

      const existingContacts = useContactsStore.getState().contacts;
      if (existingContacts.some((c) => c.id === user.id)) {
        // Already a contact — just open chat
        const existingChat = useChatsStore
          .getState()
          .chats.find((c) => c.contactId === user.id);
        if (existingChat) {
          // Select, then go to the messenger. `/chat/<id>` still resolves, but
          // only by redirecting here, so going straight there saves a hop.
          useChatsStore.getState().setActiveChat(existingChat.id);
          router.push("/chats");
        } else {
          const chatId = uuidv4();
          useChatsStore.getState().addChat({
            id: chatId,
            contactId: user.id,
            messages: [],
            unreadCount: 0,
            isHidden: false,
          });
          useChatsStore.getState().setActiveChat(chatId);
          router.push("/chats");
        }
        return;
      }

      const newContact: Contact = {
        id: user.id,
        username: user.username,
        publicKey: user.identityKey,
        exchangeKey: user.exchangeKey,
        addedAt: Date.now(),
      };

      useContactsStore.getState().addContact(newContact);
      const updatedContacts = useContactsStore.getState().contacts;

      try {
        const mk = vaultGetMasterKey();
        await saveContacts(updatedContacts, mk);
      } catch {
        // Vault may not have master key — contacts still added in-memory
      }

      const chatId = uuidv4();
      useChatsStore.getState().addChat({
        id: chatId,
        contactId: user.id,
        messages: [],
        unreadCount: 0,
        isHidden: false,
      });
      useChatsStore.getState().setActiveChat(chatId);

      setState({ status: "added", chatId });
    } catch {
      setState({ status: "error", message: t("invite.errorFailed") });
    } finally {
      setAdding(false);
    }
  }, [state, username, router]);

  return (
    <main className="auth-shell">
      <div className="auth-hero animate-fade-in">
        {state.status === "loading" && (
          <>
            <h1 className="auth-title mt-6">{t("invite.title")}</h1>
            <div className="mt-8 flex justify-center" aria-busy="true">
              <div className="w-8 h-8 border-2 mono-spinner rounded-full animate-spin" />
            </div>
          </>
        )}

        {state.status === "error" && (
          <>
            <h1 className="auth-title mt-6">{t("invite.title")}</h1>
            <p className="mt-3 text-sm text-[var(--text-secondary)] text-center">
              {state.message}
            </p>
            <button
              onClick={() => router.push("/chats")}
              className="auth-pill mt-8"
            >
              {t("invite.goToChats")}
            </button>
          </>
        )}

        {state.status === "resolved" && (
          <>
            <h1 className="auth-title mt-6">{t("invite.addContact")}</h1>

            <div className="mt-8 flex flex-col items-center gap-3">
              <div className="w-16 h-16 rounded-full border border-[var(--border)] bg-[var(--surface-strong)] flex items-center justify-center">
                <span className="text-2xl font-semibold text-[var(--text-primary)]">
                  {state.user.username[0]?.toUpperCase()}
                </span>
              </div>
              <div className="text-center">
                <p className="text-[15px] font-semibold text-[var(--text-primary)]">
                  @{state.user.username}
                </p>
                <p className="text-body text-[var(--text-muted)] mt-0.5">
                  {t("invite.wantsToConnect")}
                </p>
              </div>
            </div>

            <div className="mt-8 flex flex-col gap-3">
              <button
                onClick={() => void handleAddContact()}
                disabled={adding}
                className="auth-pill"
              >
                {adding ? t("invite.adding") : t("invite.addAndChat")}
              </button>
              <button
                onClick={() => router.push("/chats")}
                className="auth-pill-secondary"
              >
                {t("auth.skip")}
              </button>
            </div>
          </>
        )}

        {state.status === "added" && (
          <>
            <h1 className="auth-title mt-6">{t("invite.added")}</h1>
            <p className="auth-hint mt-2">{t("invite.addedHint")}</p>
            <button
              onClick={() => {
                useChatsStore.getState().setActiveChat(state.chatId);
                router.push("/chats");
              }}
              className="auth-pill mt-8"
            >
              {t("invite.openChat")}
            </button>
          </>
        )}
      </div>

    </main>
  );
}
