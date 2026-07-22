'use strict';
const { test, expect } = require('./fixtures');
const { login } = require('./helpers');

// Item 5: the ruled-paper styling on the letter textarea had zeroed its outline
// in every state, removing the only keyboard focus indicator on the app's primary
// input. Reach the field with real Tab presses (programmatic focus can bypass the
// :focus-visible heuristic) and assert the focus ring is present.
test('the letter textarea shows a keyboard focus ring', async ({ page, app }) => {
  await login(page, app);
  await page.fill('#api-key-input', 'test_browserkey');

  // Navigate the wizard to the content step, where the ruled textarea lives.
  await page.fill('#from-name', 'Jane Attorney');
  await page.fill('#from-line1', '1 Legal Plaza');
  await page.fill('#from-city', 'New York');
  await page.fill('#from-state', 'NY');
  await page.fill('#from-zip', '10001');
  await page.click('#btn-next');
  await page.locator('#recipients-list input[placeholder="John Doe"]').first().fill('John Client');
  await page.locator('#recipients-list input[placeholder="456 Oak Avenue"]').first().fill('456 Oak Ave');
  await page.locator('#recipients-list input[placeholder="Chicago"]').first().fill('Chicago');
  await page.locator('#recipients-list input[placeholder="IL"]').first().fill('IL');
  await page.locator('#recipients-list input[placeholder="60601"]').first().fill('60601');
  await page.click('#btn-next');
  await page.waitForSelector('#letter-body');

  // Tab from the Write tab to the textarea (real keyboard focus). The bounded
  // loop stays robust if the tab order between them changes.
  await page.locator('#tab-write').focus();
  for (let i = 0; i < 6; i++) {
    const active = await page.evaluate(() => document.activeElement && document.activeElement.id);
    if (active === 'letter-body') break;
    await page.keyboard.press('Tab');
  }
  await expect(page.locator('#letter-body')).toBeFocused();

  const outline = await page.locator('#letter-body').evaluate((el) => {
    const cs = getComputedStyle(el);
    return { width: cs.outlineWidth, style: cs.outlineStyle };
  });
  // A visible ring, not the suppressed outline:none the ruled styling had left.
  expect(outline.style).toBe('solid');
  expect(outline.width).toBe('2px');
});
