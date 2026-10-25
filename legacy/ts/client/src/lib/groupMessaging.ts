// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Group messaging via pairwise fan-out.
 *
 * A group message is encrypted separately for each member using the existing 1:1
 * Double Ratchet session (establishing one via X3DH on first contact), then sent
 * as N individual messages over the normal /messages/send route. The group is
 * identified by `groupId` carried INSIDE the encrypted plaintext, so the relay
 * cannot tell a group message from a 1:1 message.
 *
 * Group *membership*, however, is NOT hidden from the server: `groups` and
 * `group_members` are plaintext server tables and `GET /groups` returns full
 * membership, so the relay holds the group social graph. Only per-message
 * grouping is concealed here, not who belongs to which group. Whether that
 * association should also be hidden is an architectural decision. SEC-20260721-022.
 */

import { authApi, messagesApi } from "@/lib/api";
import type { GroupData } from "@/lib/api";
import {
  encodeRatchetEnvelope,
  type X3DHInitPayload,
} from "@/lib/ratchetPayload";
import { bundleMatchesTrustedIdentity } from "@/lib/identityPinning";
import { withSenderLock } from "@/lib/sessionLock";
import {
  deserializeSession,
  initSenderSession,
  ratchetEncrypt,
  serializeSession,
  x3dhInitiate,
} from "@/crypto/ratchet";
import {
  vaultGetSession,
  vaultGetExchangeKeyPair,
  vaultGetPublicKeys,
} from "@/crypto/keyVault";
import { verify } from "@/crypto/keys";
import { decodeBase64 } from "tweetnacl-util";
import {
  useSessionsStore,
  useContactsStore,
  type MessageReplyRef,
  type AttachmentPayload,
} from "@/stores";

export interface GroupSendResult {
  sent: number;
  failed: number;
}

export async function sendGroupMessage(params: {
  group: GroupData;
  senderId: string;
  content: string;
  timestamp: number;
  replyTo?: MessageReplyRef;
  attachment?: AttachmentPayload;
  selfDestructSeconds?: number | null;
}): Promise<GroupSendResult> {
  const {
    group,
    senderId,
    content,
    timestamp,
    replyTo,
    attachment,
    selfDestructSeconds,
  } = params;

  const recipients = group.members.filter((m) => m.user_id !== senderId);

  const plaintext = JSON.stringify({
    content,
    timestamp,
    groupId: group.id,
    selfDestruct: selfDestructSeconds ?? null,
    ...(replyTo ? { replyTo } : {}),
    ...(attachment ? { attachment } : {}),
  });
  const plaintextBytes = new TextEncoder().encode(plaintext);

  let sent = 0;
  let failed = 0;

  for (const member of recipients) {
    try {
      // A group message is fanned out over each member's own 1:1 ratchet
      // session, so it contends with that member's direct chat and with anything
      // arriving from them. Same lock, same reason as the 1:1 send path.
      await withSenderLock(member.user_id, async () => {
        const existing = vaultGetSession(member.user_id);
        const hadExistingSession = Boolean(existing);
        let session = existing ? deserializeSession(existing) : null;
        let x3dhInit: X3DHInitPayload | undefined;

        if (!session) {
          // First message to this member: X3DH (bundle signature verified) then ratchet.
          const { data: bundle, error: bundleError } = await authApi.getBundle(
            member.username,
          );
          if (bundleError || !bundle) {
            throw new Error(bundleError || "Failed to fetch bundle");
          }

          const ok = verify(
            decodeBase64(bundle.signedPrekey),
            decodeBase64(bundle.signedPrekeySignature),
            bundle.identityKey,
          );
          if (!ok) throw new Error("Invalid signed prekey signature");

          const recipientIk = bundle.exchangeIdentityKey || bundle.exchangeKey;
          if (!recipientIk) {
            throw new Error("Recipient bundle missing exchange identity key");
          }

          // Pin to the trusted contact identity when this member is already known,
          // so a malicious server cannot substitute identities (MITM). SEC-20260621-002.
          const trustedMember = useContactsStore
            .getState()
            .contacts.find((c) => c.id === member.user_id);
          if (
            !bundleMatchesTrustedIdentity(
              bundle.identityKey,
              recipientIk,
              trustedMember,
            )
          ) {
            throw new Error(
              "Group member identity does not match the trusted contact — aborting (possible MITM)",
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
        if (!session) {
          throw new Error("Failed to initialize ratchet session");
        }

        const encrypted = ratchetEncrypt(session, plaintextBytes);
        const encryptedPayload = encodeRatchetEnvelope({
          encrypted,
          timestamp,
          ...(x3dhInit ? { x3dh: x3dhInit } : {}),
        });

        const { error: sendError } = await messagesApi.send({
          senderId,
          recipientId: member.user_id,
          encryptedPayload,
        });

        if (sendError) {
          // For an already-established session, keep the advanced state to avoid
          // potential key reuse on ambiguous transport failures.
          // For first-contact X3DH, do not persist on explicit send failure:
          // otherwise retries omit X3DH and become undecryptable for recipients
          // who never received the initial handshake message.
          if (hadExistingSession) {
            useSessionsStore
              .getState()
              .upsertSession(member.user_id, serializeSession(session));
          }
          failed++;
        } else {
          useSessionsStore
            .getState()
            .upsertSession(member.user_id, serializeSession(session));
          sent++;
        }
      });
    } catch {
      failed++;
    }
  }

  return { sent, failed };
}
