'use strict';
const { test, expect } = require('./fixtures');
const { login } = require('./helpers');

test('key classification: test_ is Test, leading-whitespace live_ is Live', async ({ page, app }) => {
  await login(page, app);
  const label = page.locator('#env-label');
  const badge = page.locator('#env-badge');

  await page.fill('#api-key-input', 'test_abc123');
  await expect(label).toHaveText('Test');
  await expect(badge).not.toHaveClass(/\blive\b/);

  // The Phase 0 regression that must never return: a key pasted with leading
  // whitespace authenticates as live but must be CLASSIFIED as Live too.
  await page.fill('#api-key-input', ' live_abc123');
  await expect(label).toHaveText('Live');
  await expect(badge).toHaveClass(/\blive\b/);

  // And an unknown prefix must not read as Test.
  await page.fill('#api-key-input', 'sk_unknown');
  await expect(label).toHaveText('Live');

  await page.fill('#api-key-input', 'test_xyz');
  await expect(label).toHaveText('Test');
});
