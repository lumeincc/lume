// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

"use client";

import { useState, useEffect } from "react";
import { useAuthStore } from "@/stores";
import { profileApi, filesApi } from "@/lib/api";
import { downloadAndCacheAvatar, getCachedAvatarUrl } from "@/lib/avatarCache";
import type { Contact } from "@/crypto/storage";
import { vaultHasKeys } from "@/crypto/keyVault";

const AVATAR_FETCH_CONCURRENCY = 5;

/**
 * Runs `fn` over each item in `items` with at most `concurrency` in-flight at once.
 * Resolves when every item has been processed (or skipped on error).
 */
async function parallelMap<T, R>(
  items: T[],
  fn: (item: T) => Promise<R>,
  concurrency: number,
): Promise<void> {
  let i = 0;
  const next = async (): Promise<void> => {
    while (i < items.length) {
      const item = items[i++];
      if (item === undefined) break;
      await fn(item);
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, () => next()),
  );
}

/**
 * Loads avatars for a list of contacts.
 * Returns a Map<contactId, objectURL>.
 */
export function useContactAvatars(contacts: Contact[]): Record<string, string> {
  const hasKeys = useAuthStore((s) => s.hasIdentityKeys);
  const [avatarMap, setAvatarMap] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!vaultHasKeys() || contacts.length === 0) return;
    let cancelled = false;

    (async () => {
      await parallelMap(
        contacts,
        async (contact) => {
          if (cancelled) return;

          try {
            const res = await profileApi.get(contact.id);
            if (cancelled || !res.data?.avatarFileId) return;

            const fid = res.data.avatarFileId;
            const cached = getCachedAvatarUrl(fid);
            if (cached) {
              setAvatarMap((prev) => ({ ...prev, [contact.id]: cached }));
              return;
            }

            const url = await downloadAndCacheAvatar(fid, async () => {
              const r = await filesApi.download(fid);
              if (!r.data) return null;
              return { data: r.data.data, mimeHint: r.data.mimeHint };
            });
            if (!cancelled && url) {
              setAvatarMap((prev) => ({ ...prev, [contact.id]: url }));
            }
          } catch {
            // Best effort — skip this contact
          }
        },
        AVATAR_FETCH_CONCURRENCY,
      );
    })();

    return () => {
      cancelled = true;
    };
  }, [contacts, hasKeys]);

  return avatarMap;
}
