// SPDX-License-Identifier: LicenseRef-LUME-Source-Available
// Copyright (C) 2026 LUME Inc

import { test, expect } from '@playwright/test';

test.describe('Health Check', () => {
  test('server /api/health returns ok', async ({ request }) => {
    const response = await request.get('http://localhost:3001/api/health');
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.status).toBe('ok');
  });

  test('client root page returns 200', async ({ request }) => {
    const response = await request.get('/');
    expect(response.status()).toBe(200);
  });

  test('client /chats returns 200', async ({ request }) => {
    const response = await request.get('/chats');
    expect(response.ok()).toBeTruthy();
  });

  test('client /settings returns 200', async ({ request }) => {
    const response = await request.get('/settings');
    expect(response.ok()).toBeTruthy();
  });

  test('client /setup returns 200', async ({ request }) => {
    const response = await request.get('/setup');
    expect(response.ok()).toBeTruthy();
  });
});
