'use strict';
const assert = require('node:assert');

// Log in through the real form and land on the app. Waits for an app element
// rather than the 'load' event (which external fonts can stall).
async function login(page, app) {
  await page.goto(app.appUrl + '/login', { waitUntil: 'domcontentloaded' });
  await page.fill('#username', app.creds.username);
  await page.fill('#password', app.creds.password);
  await page.click('button[type=submit]');
  await page.waitForSelector('#api-key-input', { timeout: 15000 });
}

// Recipient inputs carry a dynamic id (r-<n>-...), and n increments after each
// "Send Another", so target them by their stable placeholders within the single
// recipient card instead of a hardcoded id.
function recipientInput(page, placeholder) {
  return page.locator('#recipients-list input[placeholder="' + placeholder + '"]');
}

// Fill the compose wizard (sender, one recipient, a written body) and stop on
// the Review step with verification settled and the Mail button ready.
async function composeToReview(page) {
  // Step 0: sender
  await page.fill('#from-name', 'Jane Attorney');
  await page.fill('#from-line1', '1 Legal Plaza');
  await page.fill('#from-city', 'New York');
  await page.fill('#from-state', 'NY');
  await page.fill('#from-zip', '10001');
  await page.click('#btn-next');
  // Step 1: recipient (id-independent selectors)
  await recipientInput(page, 'John Doe').waitFor();
  await recipientInput(page, 'John Doe').fill('John Client');
  await recipientInput(page, '456 Oak Avenue').fill('456 Oak Ave');
  await recipientInput(page, 'Chicago').fill('Chicago');
  await recipientInput(page, 'IL').fill('IL');
  await recipientInput(page, '60601').fill('60601');
  await page.click('#btn-next');
  // Step 2: content
  await page.waitForSelector('#letter-body');
  await page.fill('#letter-body', 'Dear John, this is a characterization test notice. Sincerely, Jane.');
  await page.click('#btn-next');
  // Step 3: review; wait for verification to settle so the button reads "Mail".
  await page.waitForSelector('#step-3:not(.is-hidden)');
  await page.waitForFunction(() => {
    const b = document.querySelector('#btn-next');
    return b && /Mail/.test(b.textContent) && !b.disabled;
  });
}

// ── Independent store-only ZIP reader (parses EOCD + central directory and
// verifies each entry's CRC-32). Deliberately shares no code with the writer. ──
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  return (c ^ 0xffffffff) >>> 0;
}
function readZip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) { if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; } }
  assert.notStrictEqual(eocd, -1, 'EOCD found');
  const total = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 14);
  const entries = {};
  for (let n = 0; n < total; n++) {
    assert.strictEqual(buf.readUInt32LE(p), 0x02014b50, 'central header signature');
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nameLen).toString('utf8');
    assert.strictEqual(buf.readUInt32LE(localOff), 0x04034b50, 'local header signature');
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    const data = buf.slice(dataStart, dataStart + compSize);
    assert.strictEqual(method, 0, 'store-only for ' + name);
    assert.strictEqual(crc32(data) >>> 0, crc >>> 0, 'CRC-32 matches for ' + name);
    entries[name] = data;
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

module.exports = { login, composeToReview, readZip };
