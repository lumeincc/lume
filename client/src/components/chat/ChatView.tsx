// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * One conversation: header, messages, composer, and the send path.
 *
 * This used to be a page. Opening a chat was a route change to `/chat/[id]`,
 * and that page re-declared the whole dashboard around it — left rail, chat
 * list, right rail, shell — so switching chats tore down and rebuilt every
 * panel on screen, including the list you clicked in. `GroupView` had always
 * worked the other way, rendering inside the chats page as ordinary state, and
 * there was no reason for the two to differ.
 *
 * What moved here is the conversation and nothing else. The shell stays in the
 * page that owns it, which is also what removes the duplication: LeftRail,
 * ChatListPanel, RightRail, MessengerShell, and both modals used to be written
 * out twice, once per page, and drift between the two copies was a matter of
 * time.
 *
 * The send path below is unchanged — same lock, same X3DH, same fail-closed
 * branches. It was moved, not rewritten.
 */

"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { v4 as uuidv4 } from "uuid";
import { t } from "@/lib/i18n";
import ChatHeader from "./ChatHeader";
import ChatInput from "./ChatInput";
import { MessageBubbleMemo } from "./MessageBubble";
import ProfileModal from "./ProfileModal";
import type { PendingAttachment } from "./ChatInput";
import {
  useAuthStore,
  useContactsStore,
  useChatsStore,
  useSessionsStore,
  useUIStore,
  useTypingStore,
  useBlockedStore,
  type Message,
  type MessageAttachment,
  type AttachmentPayload,
} from "@/stores";
import { messagesApi, authApi, filesApi, profileApi } from "@/lib/api";
import { downloadAndCacheAvatar, getCachedAvatarUrl } from "@/lib/avatarCache";
import { wsClient } from "@/lib/websocket";
import { decodeBase64 } from "tweetnacl-util";
import { verify } from "@/crypto/keys";
import { encodeRatchetEnvelope } from "@/lib/ratchetPayload";
import { withSenderLock } from "@/lib/sessionLock";
import { bundleMatchesTrustedIdentity } from "@/lib/identityPinning";
import {
  deserializeSession,
  initSenderSession,
  ratchetEncrypt,
  serializeSession,
  x3dhInitiate,
} from "@/crypto/ratchet";
import { computeSafetyNumber } from "@/crypto/safetyNumber";
import {
  vaultGetSession,
  vaultGetExchangeKeyPair,
  vaultGetPublicKeys,
  vaultGetMasterKey,
  vaultSetAttachmentKey,
  vaultGetAllAttachmentKeys,
} from "@/crypto/keyVault";
import {
  encryptFile,
  readFileAsUint8Array,
  isImageMime,
} from "@/lib/fileEncryption";
import { saveAttachmentKeys } from "@/crypto/storage";

interface ChatViewProps {
  chatId: string;
  /** Leaving the conversation: mobile back, deleting the contact, hiding the chat. */
  onClose: () => void;
}

export default function ChatView({ chatId, onClose }: ChatViewProps) {
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const typingStateRef = useRef(false);

  const userId = useAuthStore((s) => s.userId);
  const hasKeys = useAuthStore((s) => s.hasIdentityKeys);
  const contacts = useContactsStore((s) => s.contacts);
  const removeContact = useContactsStore((s) => s.removeContact);

  // A reply bubble needs its author's name. Resolving that with contacts.find()
  // inside the message loop is O(messages × contacts) on every render of this
  // view — 1000 messages against 50 contacts is 50,000 scans to draw one frame.
  const usernameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const c of contacts) map.set(c.id, c.username);
    return map;
  }, [contacts]);
  const upsertSession = useSessionsStore((s) => s.upsertSession);
  const deleteSession = useSessionsStore((s) => s.deleteSession);
  const chats = useChatsStore((s) => s.chats);
  const addMessage = useChatsStore((s) => s.addMessage);
  const updateMessage = useChatsStore((s) => s.updateMessage);
  const deleteMessage = useChatsStore((s) => s.deleteMessage);
  const deleteChat = useChatsStore((s) => s.deleteChat);
  const setChatHidden = useChatsStore((s) => s.setChatHidden);
  const markAsRead = useChatsStore((s) => s.markAsRead);
  const setSelfDestructTimer = useChatsStore((s) => s.setSelfDestructTimer);
  const setCryptoBanner = useUIStore((s) => s.setCryptoBanner);
  const clearCryptoBanner = useUIStore((s) => s.clearCryptoBanner);
  const showHiddenChats = useUIStore((s) => s.showHiddenChats);
  const setShowHiddenChats = useUIStore((s) => s.setShowHiddenChats);

  const [messageText, setMessageText] = useState("");
  const [sending, setSending] = useState(false);
  const [showOptions, setShowOptions] = useState(false);
  const [selfDestructTime, setSelfDestructTime] = useState<number | null>(null);
  const [showProfile, setShowProfile] = useState(false);
  const [replyingTo, setReplyingTo] = useState<Message | null>(null);
  const [pendingAttachment, setPendingAttachment] =
    useState<PendingAttachment | null>(null);
  const [contactAvatarUrl, setContactAvatarUrl] = useState<string | null>(null);

  // The id now arrives as a prop rather than a URL segment, but it still ends up
  // here from `/chat/[id]` on a deep link, so it is still checked before it is
  // used to look anything up.
  const isValidChatId =
    /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/.test(
      chatId,
    );
  const chat = isValidChatId ? chats.find((c) => c.id === chatId) : undefined;
  const contact = contacts.find((c) => c.id === chat?.contactId);
  const contactId = contact?.id;

  const isContactBlocked = useBlockedStore((s) =>
    contactId ? !!s.blockedIds[contactId] : false,
  );

  const isTyping = useTypingStore((s) =>
    contactId ? (s.typingUsers[contactId] ?? false) : false,
  );
  const pubKeys = vaultGetPublicKeys();
  const safetyNumber =
    pubKeys && contact
      ? computeSafetyNumber({
          mySigningPublicKey: pubKeys.signingPublicKey,
          myExchangeIdentityPublicKey: pubKeys.exchangePublicKey,
          theirSigningPublicKey: contact.publicKey,
          theirExchangeIdentityPublicKey: contact.exchangeKey,
        })
      : null;

  // Load contact avatar
  useEffect(() => {
    if (!contactId || !hasKeys) return;
    let cancelled = false;

    (async () => {
      try {
        const res = await profileApi.get(contactId);
        if (cancelled || !res.data?.avatarFileId) return;

        const fid = res.data.avatarFileId;
        const cached = getCachedAvatarUrl(fid);
        if (cached) {
          setContactAvatarUrl(cached);
          return;
        }

        const url = await downloadAndCacheAvatar(fid, async () => {
          const r = await filesApi.download(fid);
          if (!r.data) return null;
          return { data: r.data.data, mimeHint: r.data.mimeHint };
        });
        if (!cancelled) setContactAvatarUrl(url);
      } catch {
        // Best effort
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [contactId, hasKeys]);

  useEffect(() => {
    markAsRead(chatId);

    // Send read receipts for unread messages from the contact
    if (contactId) {
      const currentChat = useChatsStore
        .getState()
        .chats.find((c) => c.id === chatId);
      if (currentChat) {
        const unreadFromContact = currentChat.messages.filter(
          (m) => m.senderId === contactId && m.status !== "read",
        );
        if (unreadFromContact.length > 0) {
          wsClient.sendReadReceipt(
            contactId,
            unreadFromContact.map((m) => m.id),
          );
        }
      }
    }
  }, [chatId, contactId, markAsRead]);

  // The timer is per-chat, so a different chat has to re-read it rather than
  // inherit the one left over from the last conversation.
  useEffect(() => {
    setSelfDestructTime(null);
  }, [chatId]);

  useEffect(() => {
    if (!chat) return;
    if (
      selfDestructTime === null &&
      typeof chat.selfDestructTimer === "number"
    ) {
      setSelfDestructTime(chat.selfDestructTimer);
    }
  }, [chat, selfDestructTime]);

  useEffect(() => {
    if (!chat) return;
    if (chat.isHidden && !showHiddenChats) {
      onClose();
    }
  }, [chat, showHiddenChats, onClose]);

  useEffect(() => {
    const container = messagesContainerRef.current;
    if (!container) {
      messagesEndRef.current?.scrollIntoView({ behavior: "auto" });
      return;
    }
    // Only auto-scroll if the user is already near the bottom (within 120px).
    const isNearBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight <
      120;
    if (isNearBottom) {
      messagesEndRef.current?.scrollIntoView({ behavior: "auto" });
    }
  }, [chat?.messages.length]);

  // Reduce WS traffic: send typing=true once when user starts typing,
  // then typing=false after a short inactivity window.
  useEffect(() => {
    if (!contactId) return undefined;

    const isTypingNow = messageText.trim().length > 0;

    if (!isTypingNow) {
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
        typingTimeoutRef.current = null;
      }
      if (typingStateRef.current) {
        typingStateRef.current = false;
        wsClient.sendTyping(contactId, false);
      }
      return undefined;
    }

    if (!typingStateRef.current) {
      typingStateRef.current = true;
      wsClient.sendTyping(contactId, true);
    }

    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
    typingTimeoutRef.current = setTimeout(() => {
      typingTimeoutRef.current = null;
      if (typingStateRef.current) {
        typingStateRef.current = false;
        wsClient.sendTyping(contactId, false);
      }
    }, 1200);

    return undefined;
  }, [messageText, contactId]);

  useEffect(() => {
    return () => {
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
        typingTimeoutRef.current = null;
      }
      if (contactId && typingStateRef.current) {
        typingStateRef.current = false;
        wsClient.sendTyping(contactId, false);
      }
    };
  }, [contactId]);

  // Switching chats without unmounting means the composer no longer starts
  // empty on its own. Left alone, a half-typed message would follow you into
  // someone else's conversation and could be sent to the wrong contact.
  useEffect(() => {
    setMessageText("");
    setReplyingTo(null);
    setPendingAttachment((current) => {
      if (current?.preview) URL.revokeObjectURL(current.preview);
      return null;
    });
    setShowOptions(false);
    setShowProfile(false);
  }, [chatId]);

  const handleAttach = useCallback((file: File) => {
    const preview = isImageMime(file.type)
      ? URL.createObjectURL(file)
      : undefined;
    setPendingAttachment({ file, preview });
  }, []);

  const handleCancelAttachment = useCallback(() => {
    if (pendingAttachment?.preview) {
      URL.revokeObjectURL(pendingAttachment.preview);
    }
    setPendingAttachment(null);
  }, [pendingAttachment]);

  const handleDeleteMessage = useCallback(
    (messageId: string) => {
      if (chatId) {
        deleteMessage(chatId, messageId);
      }
    },
    [chatId, deleteMessage],
  );

  const handleReply = useCallback((message: Message) => {
    setReplyingTo(message);
  }, []);

  const handleSend = async () => {
    const hasText = messageText.trim().length > 0;
    const hasAttachment = !!pendingAttachment;
    if ((!hasText && !hasAttachment) || !contact || !userId || !hasKeys) return;

    setSending(true);

    const messageId = uuidv4();
    const timestamp = Date.now();
    const outgoingText = messageText;

    // Upload and encrypt file attachment if present
    let attachmentMeta: MessageAttachment | undefined;
    let attachmentPayload: AttachmentPayload | undefined;
    if (pendingAttachment) {
      try {
        const fileData = await readFileAsUint8Array(pendingAttachment.file);
        const encrypted = await encryptFile(
          fileData,
          pendingAttachment.file.type,
          pendingAttachment.file.name,
        );
        const { data: uploadResult, error: uploadError } =
          await filesApi.upload(
            encrypted.ciphertext,
            encrypted.mimeType,
            // 1:1 attachment: restrict download to the recipient (and uploader). SEC-20260621-006.
            contactId ? { recipientId: contactId } : undefined,
          );
        if (uploadError || !uploadResult) {
          throw new Error(uploadError || "File upload failed");
        }
        // Metadata only goes into message/Zustand state. SEC-20260621-004.
        attachmentMeta = {
          fileId: uploadResult.fileId,
          fileName: encrypted.fileName,
          mimeType: encrypted.mimeType,
          size: encrypted.originalSize,
        };
        // The decrypt key/nonce travel E2E inside the plaintext; a local copy is
        // kept in the vault (keyed by fileId) + persisted — never in message state.
        attachmentPayload = {
          ...attachmentMeta,
          key: encrypted.key,
          nonce: encrypted.nonce,
        };
        vaultSetAttachmentKey(
          uploadResult.fileId,
          encrypted.key,
          encrypted.nonce,
        );
        void saveAttachmentKeys(
          vaultGetAllAttachmentKeys(),
          vaultGetMasterKey(),
        );
      } catch (err) {
        if (process.env.NODE_ENV !== "production")
          console.error("File upload error:", err);
        setSending(false);
        return;
      }
    }

    const msgType = attachmentMeta
      ? isImageMime(attachmentMeta.mimeType)
        ? "image"
        : "file"
      : "text";

    const message: Message = {
      id: messageId,
      chatId,
      senderId: userId,
      content: outgoingText,
      type: msgType as Message["type"],
      timestamp,
      status: "sending",
      selfDestructAt: selfDestructTime
        ? timestamp + selfDestructTime * 1000
        : undefined,
      replyTo: replyingTo
        ? {
            messageId: replyingTo.id,
            content: replyingTo.content,
            senderId: replyingTo.senderId,
          }
        : undefined,
      attachment: attachmentMeta,
    };

    addMessage(chatId, message);
    setMessageText("");
    setReplyingTo(null);
    if (pendingAttachment?.preview) {
      URL.revokeObjectURL(pendingAttachment.preview);
    }
    setPendingAttachment(null);

    try {
      const replyRef = replyingTo
        ? {
            messageId: replyingTo.id,
            content: replyingTo.content.slice(0, 200),
            senderId: replyingTo.senderId,
          }
        : undefined;
      const plaintext = JSON.stringify({
        content: outgoingText,
        timestamp,
        selfDestruct: selfDestructTime ?? null,
        ...(replyRef ? { replyTo: replyRef } : {}),
        ...(attachmentPayload ? { attachment: attachmentPayload } : {}),
      });
      const plaintextBytes = new TextEncoder().encode(plaintext);

      // Everything that reads, advances and stores the ratchet session runs
      // under the same per-contact lock the receive path uses. Without it a
      // message arriving mid-send overwrote the DH ratchet step it had just
      // committed, and two quick sends shared a message number — in both cases
      // a message is lost and nothing reports it. The attachment upload above is
      // deliberately outside the lock: it can take a while, and it touches no
      // session state.
      await withSenderLock(contact.id, async () => {
        const existing = contactId ? vaultGetSession(contactId) : undefined;

        let session = existing ? deserializeSession(existing) : null;
        let x3dhInit:
          | {
              senderIdentityKey: string;
              senderEphemeralKey: string;
              recipientOneTimePreKey?: string | null;
              recipientSignedPreKey?: string;
            }
          | undefined;

        if (!session) {
          // First message to this contact: do X3DH (bundle is signed) and start a ratchet session.
          const { data: bundle, error: bundleError } = await authApi.getBundle(
            contact.username,
          );
          if (bundleError || !bundle) {
            throw new Error(bundleError || "Failed to fetch bundle");
          }

          const ok = verify(
            decodeBase64(bundle.signedPrekey),
            decodeBase64(bundle.signedPrekeySignature),
            bundle.identityKey,
          );
          if (!ok) {
            throw new Error("Invalid signed prekey signature");
          }

          const recipientIk = bundle.exchangeIdentityKey || bundle.exchangeKey;
          if (!recipientIk) {
            throw new Error("Recipient bundle missing exchange identity key");
          }

          // Pin the bundle to the already-trusted contact identity so a malicious
          // server cannot substitute a different identity (MITM). SEC-20260621-002.
          if (
            !bundleMatchesTrustedIdentity(
              bundle.identityKey,
              recipientIk,
              contact,
            )
          ) {
            throw new Error(
              "Recipient identity does not match the trusted contact — aborting (possible MITM)",
            );
          }

          const { sharedSecret, ephemeralPublicKey } = x3dhInitiate(
            vaultGetExchangeKeyPair(),
            {
              identityKey: recipientIk,
              signingKey: bundle.identityKey,
              signedPreKey: bundle.signedPrekey,
              signature: bundle.signedPrekeySignature,
              oneTimePreKey: bundle.oneTimePrekey,
            },
          );

          session = initSenderSession(sharedSecret, bundle.signedPrekey);
          // Fail closed: the vault returns null when it is locked, and asserting
          // that away turned a locked vault into a TypeError partway through
          // building the X3DH header, after the session had already been created.
          const senderPublicKeys = vaultGetPublicKeys();
          if (!senderPublicKeys) {
            throw new Error('Key vault is locked; cannot start a session');
          }
          x3dhInit = {
            senderIdentityKey: senderPublicKeys.exchangePublicKey,
            senderEphemeralKey: ephemeralPublicKey,
            recipientOneTimePreKey: bundle.oneTimePrekey ?? null,
            // Tell the recipient which SPK we used so they can respond with the
            // matching key during its grace window. SEC-20260621-022.
            recipientSignedPreKey: bundle.signedPrekey,
          };
        }

        const encrypted = ratchetEncrypt(session, plaintextBytes);
        const encryptedPayload = encodeRatchetEnvelope({
          encrypted,
          timestamp,
          selfDestruct: selfDestructTime,
          ...(x3dhInit ? { x3dh: x3dhInit } : {}),
        });

        const { data, error } = await messagesApi.send({
          senderId: userId,
          recipientId: contact.id,
          encryptedPayload,
        });

        if (error) {
          // Same desync guard as group fan-out (lib/groupMessaging.ts): never
          // persist a fresh X3DH session on a failed first send — a retry must
          // re-send the handshake, otherwise the recipient can never decrypt.
          // For an already-established session, keep the advance to avoid reusing
          // a message key on an ambiguous transport failure.
          if (contactId && existing) {
            upsertSession(contactId, serializeSession(session));
          }
          updateMessage(chatId, messageId, { status: "failed" });
        } else {
          if (contactId) {
            upsertSession(contactId, serializeSession(session));
          }
          clearCryptoBanner();
          updateMessage(chatId, messageId, {
            status: data?.delivered ? "delivered" : "sent",
          });
        }
      });
    } catch (sendError) {
      if (process.env.NODE_ENV !== "production")
        console.error("Send message error:", sendError);
      const msg =
        sendError instanceof Error ? sendError.message : String(sendError);
      if (
        msg.includes("bundle") ||
        msg.includes("signed prekey") ||
        msg.includes("signature") ||
        msg.includes("exchange identity") ||
        msg.includes("Sending chain")
      ) {
        setCryptoBanner({
          level: "warning",
          message: t("chat.crypto.noSecureSession"),
        });
      }
      updateMessage(chatId, messageId, { status: "failed" });
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    // The send button is disabled while a send is in flight, but the textarea is
    // not — so Enter was the one way to start a second send over the first.
    if (e.key === "Enter" && !e.shiftKey && !sending) {
      e.preventDefault();
      void handleSend();
    }
  };

  const handleSelectTimer = (value: number | null) => {
    setSelfDestructTime(value);
    setSelfDestructTimer(chatId, value ?? undefined);
  };

  const handleDeleteContact = () => {
    if (!contact || !contactId) return;
    deleteChat(chatId);
    deleteSession(contactId);
    removeContact(contactId);
    setShowProfile(false);
    onClose();
  };

  const handleHideChat = () => {
    const nextHidden = !chat?.isHidden;
    setChatHidden(chatId, nextHidden);
    if (nextHidden) {
      setShowHiddenChats(false);
      setShowProfile(false);
      onClose();
    }
  };

  if (!chat || !contact) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <p className="text-[var(--text-secondary)] text-sm">
            {t("chat.notFound")}
          </p>
          <button onClick={onClose} className="mt-4 apple-button-secondary px-6">
            {t("auth.back")}
          </button>
        </div>
      </div>
    );
  }

  // Synchronous guard: never paint a hidden chat's content before the effect
  // above closes it. Rendering an empty panel keeps hidden message text out of
  // the DOM entirely while that happens. SEC-20260621-017.
  if (chat.isHidden && !showHiddenChats) {
    return <div className="h-full min-h-0 overflow-hidden" />;
  }

  return (
    <div className="h-full min-h-0 overflow-hidden flex flex-col">
      <ChatHeader
        contact={contact}
        avatarUrl={contactAvatarUrl}
        isTyping={isTyping}
        selfDestructTime={selfDestructTime}
        showOptions={showOptions}
        onBack={onClose}
        onOpenProfile={() => setShowProfile(true)}
        onToggleOptions={() => setShowOptions((v) => !v)}
        onSelectTimer={handleSelectTimer}
      />

      <main
        ref={messagesContainerRef}
        className="flex-1 min-h-0 overflow-y-auto px-3 sm:px-5 md:px-6 py-4 sm:py-5 space-y-2"
      >
        {chat.messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center px-6">
            <div className="w-16 h-16 rounded-full border border-[var(--border)] bg-[var(--surface-strong)] flex items-center justify-center text-[var(--text-muted)]">
              <svg
                className="w-8 h-8"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="1.8"
                  d="M21 15a4 4 0 01-4 4H8l-5 3V7a4 4 0 014-4h10a4 4 0 014 4v8z"
                />
              </svg>
            </div>
            <p className="mt-4 text-body font-semibold text-[var(--text-primary)]">
              {t("chat.noMessagesYet")}
            </p>
            <p className="mt-1 text-xs text-[var(--text-muted)]">
              {t("chat.sendFirst")}
            </p>
          </div>
        ) : (
          <>
            {chat.messages.map((m) => {
              let replyAuthorName: string | undefined;
              if (m.replyTo) {
                if (m.replyTo.senderId === userId) {
                  replyAuthorName = t("chat.replyToYou");
                } else {
                  replyAuthorName =
                    usernameById.get(m.replyTo.senderId) ??
                    t("chat.replyToUnknown");
                }
              }
              return (
                <MessageBubbleMemo
                  key={m.id}
                  message={m}
                  isMine={m.senderId === userId}
                  onDelete={handleDeleteMessage}
                  onReply={handleReply}
                  replyAuthorName={replyAuthorName}
                />
              );
            })}
            <div ref={messagesEndRef} />
          </>
        )}
      </main>

      <ChatInput
        messageText={messageText}
        sending={sending}
        selfDestructTime={selfDestructTime}
        replyingTo={replyingTo}
        userId={userId}
        contact={contact}
        onMessageChange={setMessageText}
        onSend={() => void handleSend()}
        onKeyDown={handleKeyDown}
        onToggleOptions={() => setShowOptions((v) => !v)}
        onCancelReply={() => setReplyingTo(null)}
        attachment={pendingAttachment}
        onAttach={handleAttach}
        onCancelAttachment={handleCancelAttachment}
      />

      <ProfileModal
        isOpen={showProfile}
        onClose={() => setShowProfile(false)}
        contact={contact}
        chat={chat}
        safetyNumber={safetyNumber}
        isContactBlocked={isContactBlocked}
        onDeleteContact={handleDeleteContact}
        onHideChat={handleHideChat}
        avatarUrl={contactAvatarUrl}
      />
    </div>
  );
}
