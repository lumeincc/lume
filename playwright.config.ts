// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  timeout: 30_000,

  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    /* Without this, an action waits as long as the test has left. One control
       that never becomes clickable then burns the whole budget and reports
       "test timeout exceeded" — which names the symptom and hides the cause.
       Bounded, a stuck click says which locator it was still waiting for. */
    actionTimeout: 15_000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  /* Start both servers before running tests. The timeout is generous because a
     cold Next.js dev start can take well over the old 30s.

     Reuse is a local convenience only. Locally, an already-running dev server
     is the working tree you are trying to verify, so picking it up saves the
     cold start and tests the right thing. In CI it is the opposite: the runner
     has its own checkout, so reusing whatever happens to be listening would
     report on a different tree than the commit under test. That mattered the
     moment CI moved onto a machine that also runs a dev server. */
  webServer: [
    {
      command: 'cd server && npm start',
      url: 'http://localhost:3001/api/health',
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
    {
      command: 'cd client && npm run dev',
      url: 'http://localhost:3000',
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
    },
  ],
});
