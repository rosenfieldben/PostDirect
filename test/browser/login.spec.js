'use strict';
const { test, expect } = require('./fixtures');

test('login: wrong password shows the error, correct password reaches the app', async ({ page, app }) => {
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
});
