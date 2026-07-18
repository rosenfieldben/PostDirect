'use strict';
const { defineConfig } = require('@playwright/test');
const fs = require('node:fs');

// Use the pre-provisioned chromium when this image ships it (at
// /opt/pw-browsers/chromium); otherwise fall back to Playwright's managed
// browser, which GitHub Actions provisions with `npx playwright install
// chromium`. Keeping executablePath conditional lets one config serve both.
const localChromium = '/opt/pw-browsers/chromium';
const executablePath = fs.existsSync(localChromium) ? localChromium : undefined;

module.exports = defineConfig({
  testDir: './test/browser',
  // One worker: the fixture boots a real app + stub upstream once per worker,
  // and the suite is deliberately small, so serial keeps it deterministic and
  // well under the two-minute budget. No retries so per-test audit state stays
  // predictable (a retried send would see its own prior fingerprint).
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  reporter: process.env.CI ? 'line' : 'list',
  use: {
    headless: true,
    actionTimeout: 10_000,
    launchOptions: executablePath ? { executablePath } : {},
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
