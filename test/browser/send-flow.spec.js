'use strict';
const fs = require('node:fs');
const { test, expect } = require('./fixtures');
const { login, composeToReview, readZip } = require('./helpers');

test('send flow: honest labels, proof export, and the duplicate warning', async ({ page, app }) => {
  await login(page, app);
  await page.fill('#api-key-input', 'test_browserkey');

  // ── Send a letter through the wizard ──
  await composeToReview(page);
  await page.click('#btn-next'); // Send (no prior send yet, so no duplicate prompt)
  await page.waitForSelector('#step-4:not(.is-hidden)');

  // A create is "Queued", never "Mailed": the Phase 1 honest-label rule. The
  // redesign titles the state "Gone to press." while the per-letter status tag
  // stays the honest "Queued".
  await expect(page.locator('#success-title')).toContainText('Gone to press.');
  await expect(page.locator('#success-results .status-badge').first()).toHaveText('Queued');

  // ── History shows an honest lifecycle label (not "Mailed"/"Delivered") ──
  await page.click('#view-history-tab');
  const badge = page.locator('#history-list .status-badge').first();
  await expect(badge).toBeVisible();
  const badgeText = (await badge.textContent()).trim();
  expect(badgeText).not.toMatch(/Mailed|Delivered/);
  expect(badgeText).toBe('Created');

  // ── Proof export downloads a ZIP the independent reader validates ──
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('#history-list [data-proof]').first().click(),
  ]);
  const zipPath = await download.path();
  const entries = readZip(fs.readFileSync(zipPath));
  expect(entries['manifest.json']).toBeTruthy();
  expect(entries['request-body.bin']).toBeTruthy();
  const manifest = JSON.parse(entries['manifest.json'].toString('utf8'));
  expect(manifest.hasLocalRecord).toBe(true);

  // ── Duplicate warning ──
  // A page RELOAD resets the ephemeral recipient counter, so re-entering the
  // identical letter reproduces the exact fingerprint of the first send (the
  // fingerprint intentionally includes the recipient id, which is why the
  // in-session "Send Another" is treated as a new letter instead). The durable
  // server record then flags the prior send.
  await page.goto(app.appUrl + '/', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#api-key-input');
  await page.fill('#api-key-input', 'test_browserkey');
  let dialogMessage = null;
  page.on('dialog', (d) => { dialogMessage = d.message(); d.dismiss(); });
  await composeToReview(page); // identical letter, recipient id back to 1
  await page.click('#btn-next'); // Send -> duplicate check -> confirm() dialog
  await expect.poll(() => dialogMessage, { timeout: 10_000 }).toContain('Possible duplicate send');
  // Dialog dismissed, so no second letter was sent: still on the review step.
  await expect(page.locator('#step-3')).toBeVisible();
});
