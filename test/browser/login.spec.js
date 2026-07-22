'use strict';
const { test, expect } = require('./fixtures');

test('login: wrong password shows the error, correct password reaches the app', async ({ page, app }) => {
  // Collect every request the page issues across login + app load. Self-hosting
  // the font is exactly so the browser talks to one origin: a stray third-party
  // request (a former font-CDN call, say) would surface here. data: and about:
  // are page-internal schemes, not network origins, so they are ignored.
  const appHost = new URL(app.appUrl).host;
  const foreign = [];
  page.on('request', (req) => {
    let u;
    try { u = new URL(req.url); } catch (e) { return; }
    if (u.protocol === 'data:' || u.protocol === 'about:') return;
    if (u.host !== appHost) foreign.push(req.url);
  });

  await page.goto(app.appUrl + '/login', { waitUntil: 'domcontentloaded' });
  await page.fill('#username', app.creds.username);
  await page.fill('#password', 'definitely-wrong');
  await page.click('button[type=submit]');
  await expect(page.locator('.error')).toContainText('Invalid username or password');

  await page.fill('#username', app.creds.username);
  await page.fill('#password', app.creds.password);
  await page.click('button[type=submit]');
  // The app shell rendered (the first wizard step heading, per the redesign).
  await expect(page.locator('#step-0 .section-title')).toContainText('The return address.');

  // Let the app page finish requesting its css/js/fonts, then assert that every
  // request stayed on the app's own origin.
  await page.waitForLoadState('networkidle');
  expect(foreign, 'page must talk to exactly one origin; foreign requests: ' + foreign.join(', ')).toEqual([]);
});
