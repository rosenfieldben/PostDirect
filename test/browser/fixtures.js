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
  // No page-request routing: the font is self-hosted now, so the page makes no
  // external font requests to intercept. The old abort route (which kept the
  // unreachable third-party font CDN from stalling navigation) is gone with the
  // dependency it worked around. login.spec asserts the single-origin property.
});

module.exports = { test, expect: base.expect };
