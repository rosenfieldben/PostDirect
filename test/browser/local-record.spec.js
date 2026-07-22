'use strict';
// Item 4: the "Local record" section in the History tab. Renders the durable
// server-side ledger and, when a write-ahead intent has no recorded outcome,
// surfaces it in a reconciliation banner with a working Resolve control. We seed
// a dangling intent directly into the store the running app reads (there is no
// API to mint one, by design), then drive the banner's resolve flow.
const { test, expect } = require('./fixtures');
const { login } = require('./helpers');

test('local record: an unconfirmed intent surfaces and can be reconciled', async ({ page, app }) => {
  const store = require('../../lib/store.js');
  const intentId = store.writeSendIntent(app.dataDir, {
    lobPath: '/v1/letters',
    reqHeaders: { 'idempotency-key': 'browser-idem-1' },
    reqBuf: Buffer.from('browser dangling intent bytes'),
  }, Date.now());

  await login(page, app);
  await page.click('#view-history-tab');

  // The section exists and the banner surfaces the dangling intent by its data.
  await expect(page.locator('#local-record-title')).toBeVisible();
  const banner = page.locator('#intent-banner');
  await expect(banner).toBeVisible();
  await expect(banner).toContainText('need reconciliation');
  await expect(banner).toContainText('browser-idem-1');
  const form = banner.locator('form.intent-resolve[data-intent="' + intentId + '"]');
  await expect(form).toBeVisible();

  // Reconcile it as "not sent" with a note.
  await form.locator('.intent-resolution').selectOption('not_sent');
  await form.locator('.intent-note').fill('checked Lob, nothing there');
  await form.locator('button[type="submit"]').click();

  // The banner clears (nothing left unresolved) and a Reconciled row is now in
  // the ledger, proving the resolution was recorded and the ledger re-rendered.
  await expect(page.locator('#intent-banner')).toBeHidden();
  await expect(page.locator('#ledger-list')).toContainText('Reconciled');
});
