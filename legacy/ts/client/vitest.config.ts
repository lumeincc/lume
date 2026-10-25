// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    // Default environment is node; hooks tests override to jsdom via @vitest-environment docblock
    environment: 'node',
    globals: true,
    setupFiles: ['./src/__tests__/setup.ts'],
    exclude: ['e2e/**', 'node_modules/**'],
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/__tests__/**', 'src/**/*.d.ts'],
      reporter: ['text-summary', 'lcov'],
      // Floors, not targets. Each number sits a couple of points under what was
      // measured on 2026-08-05, so ordinary churn does not red the branch but a
      // real drop does. Raise them when coverage rises; never lower them to make
      // a run go green.
      //
      // Measured:  global 30.54/22.77/30.11/31.51, crypto 83.88/70.85/91.83/85.83
      //
      // The global figure is dragged down by UI components, which are largely
      // untested; the crypto core is held to its own, much higher bar because
      // that is where a regression is not a broken screen but a broken promise.
      thresholds: {
        statements: 30,
        branches: 22,
        functions: 29,
        lines: 31,
        'src/crypto/**': {
          statements: 82,
          branches: 68,
          functions: 90,
          lines: 84,
        },
      },
    },
    environmentOptions: {
      jsdom: {
        resources: 'usable',
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
