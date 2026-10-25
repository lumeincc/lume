// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Zod schemas for /files routes.
 */

import { z } from 'zod'
import { UuidSchema } from './common'

const MAX_BASE64_LENGTH = Math.ceil((5 * 1024 * 1024) / 3) * 4 + 4 // ~6.67MB base64 for 5MB binary

// POST /files/upload
export const UploadFileBodySchema = z.object({
  data: z
    .string()
    .min(1, 'File data must not be empty')
    .max(MAX_BASE64_LENGTH, 'File data exceeds size limit'),
  mimeHint: z
    .string()
    .regex(/^[a-z]+\/[a-z0-9.+-]+$/, 'Invalid MIME type format')
    .optional(),
  recipientId: UuidSchema.optional(),
  isPublic: z.boolean().optional(),
})

// GET /files/:fileId
export const FileIdParamSchema = z.object({
  fileId: UuidSchema,
})
