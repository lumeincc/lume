// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/** UUID v4 shape — every id the API carries in a path is one of these. */
const UUID_RE = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g

/**
 * Redacts identifiers from request paths before they are logged
 * (SEC-20260621-021, SEC-20260721-027).
 *
 * Redaction is by *pattern class*, not by named route, so a new identifier-bearing
 * endpoint is covered by default rather than by someone remembering to add it:
 *   - invite tokens after `/resolve-invite/` (opaque, high-entropy),
 *   - any UUID-shaped segment (`userId`, `fileId`, `groupId`, `messageId`, …),
 *   - the username after `/user/` or `/check/` (not UUID-shaped).
 */
export function redactSensitivePath(path: string): string {
  return (
    path
      .replace(/\/(resolve-invite)\/[^/?]+/g, '/$1/:token')
      .replace(UUID_RE, ':id')
      // Skip a segment already redacted to `:id` above.
      .replace(/\/(user|check)\/(?!:)[^/?]+/g, '/$1/:username')
  )
}
