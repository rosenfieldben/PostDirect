'use strict';
const base = require('@playwright/test');
const { startServers } = require('./servers');

// Worker-scoped app fixture: boots the app + stub once per worker and tears
// them down after. With workers:1 that is a single boot for the whole suite.
const test = base.test.extend({
  app: [async ({}, use) => {
    const servers = await startServers();
    await use(servers);
    await servers.stop();
  }, { scope: 'worker' }],
  // Google Fonts are unreachable in the sandboxed browser and would otherwise
  // stall the page 'load' event (connection resets), making navigation waits
  // flaky. Abort those external requests so pages load deterministically and
  // fast; the app is fully functional with fallback fonts.
  page: async ({ page }, use) => {
    await page.route(/fonts\.(googleapis|gstatic)\.com/, (r) => r.abort());
    await use(page);
  },
});

module.exports = { test, expect: base.expect };
