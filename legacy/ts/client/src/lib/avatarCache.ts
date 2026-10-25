// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * In-memory cache for downloaded avatar object URLs.
 * Maps fileId -> object URL string.
 *
 * Uses LRU-like eviction based on Map insertion order to cap memory usage.
 * Object URLs are revoked when entries are evicted or the cache is cleared.
 */

const MAX_CACHE_SIZE = 200;

const cache = new Map<string, string>();

/** Pending downloads keyed by fileId to avoid duplicate parallel fetches. */
const pending = new Map<string, Promise<string | null>>();

/**
 * Evict the oldest entry from the cache and revoke its object URL.
 */
function evictOldest(): void {
  const oldest = cache.entries().next();
  if (!oldest.done) {
    const [key, url] = oldest.value;
    URL.revokeObjectURL(url);
    cache.delete(key);
  }
}

/**
 * Insert or refresh an entry in the cache, enforcing the max size.
 * Re-inserting an existing key moves it to the end (most-recently-used).
 */
function cacheSet(fileId: string, url: string): void {
  // If the key already exists, delete it first so re-insertion moves it to the end
  if (cache.has(fileId)) {
    cache.delete(fileId);
  }

  // Evict oldest entries until we have room
  while (cache.size >= MAX_CACHE_SIZE) {
    evictOldest();
  }

  cache.set(fileId, url);
}

export function getCachedAvatarUrl(fileId: string): string | undefined {
  const url = cache.get(fileId);
  if (url !== undefined) {
    // Move to end (most-recently-used) on access
    cache.delete(fileId);
    cache.set(fileId, url);
  }
  return url;
}

export function setCachedAvatarUrl(fileId: string, url: string): void {
  cacheSet(fileId, url);
}

export function hasCachedAvatar(fileId: string): boolean {
  return cache.has(fileId);
}

/**
 * Revoke all cached object URLs and clear the cache.
 * Call this on logout or when the component tree unmounts to free blob memory.
 */
export function cleanupAvatarCache(): void {
  for (const url of cache.values()) {
    URL.revokeObjectURL(url);
  }
  cache.clear();
}

/**
 * Download an avatar by fileId, cache the resulting object URL, and return it.
 * De-duplicates concurrent requests for the same fileId.
 */
export async function downloadAndCacheAvatar(
  fileId: string,
  downloadFn: () => Promise<{ data: string; mimeHint: string } | null>,
): Promise<string | null> {
  const existing = cache.get(fileId);
  if (existing) {
    // Move to end (most-recently-used)
    cache.delete(fileId);
    cache.set(fileId, existing);
    return existing;
  }

  const inflight = pending.get(fileId);
  if (inflight) return inflight;

  const promise = (async () => {
    try {
      const result = await downloadFn();
      if (!result) return null;

      const binary = atob(result.data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: result.mimeHint || "image/png" });
      const url = URL.createObjectURL(blob);
      cacheSet(fileId, url);
      return url;
    } catch {
      return null;
    } finally {
      pending.delete(fileId);
    }
  })();

  pending.set(fileId, promise);
  return promise;
}
