// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

/**
 * Express middleware for Zod schema validation.
 * Validates body/params at the boundary — handlers receive typed, clean data.
 */

import type { Request, Response, NextFunction } from 'express'
import type { ZodSchema } from 'zod'

export function validateBody<T extends ZodSchema>(schema: T) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body)
    if (!result.success) {
      const issue = result.error.issues[0]
      const msg = issue
        ? issue.path.length > 0
          ? `${String(issue.path.join('.'))}: ${issue.message}`
          : issue.message
        : 'Validation error'
      res.status(400).json({ error: msg })
      return
    }
    req.body = result.data
    next()
  }
}

export function validateParams<T extends ZodSchema>(schema: T) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.params)
    if (!result.success) {
      const issue = result.error.issues[0]
      const msg = issue
        ? issue.path.length > 0
          ? `${String(issue.path.join('.'))}: ${issue.message}`
          : issue.message
        : 'Validation error'
      res.status(400).json({ error: msg })
      return
    }
    next()
  }
}

export function validateQuery<T extends ZodSchema>(schema: T) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.query)
    if (!result.success) {
      const issue = result.error.issues[0]
      const msg = issue
        ? issue.path.length > 0
          ? `${String(issue.path.join('.'))}: ${issue.message}`
          : issue.message
        : 'Validation error'
      res.status(400).json({ error: msg })
      return
    }
    ;(req as Request & { validatedQuery?: unknown }).validatedQuery = result.data
    next()
  }
}
