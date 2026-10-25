// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 30_000,
    include: ['test/**/*.test.ts'],
    fileParallelism: false,
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/**/*.d.ts'],
      reporter: ['text-summary', 'lcov'],
      // Floors, not targets. A couple of points under what was measured on
      // 2026-08-05 (59.37/50.76/65.67/60.22), so churn does not red the branch
      // but a real drop does. Raise them as coverage rises; never lower them to
      // make a run go green.
      thresholds: {
        statements: 57,
        branches: 48,
        functions: 63,
        lines: 58,
      },
    },
  },
});

