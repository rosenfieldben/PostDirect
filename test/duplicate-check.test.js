'use strict';
// Fix for review finding #5: confirmDuplicateSends checks every recipient's
// fingerprint against /api/sends in PARALLEL (was one serial round trip per
// recipient). Imported from the shipped js/duplicate.mjs with fetch/confirm stubbed.
const test = require('node:test');
const assert = require('node:assert');

// Import the REAL confirmDuplicateSends from the shipped ES module
// (js/duplicate.mjs). It uses the ambient `fetch` and `confirm` globals (present
// in the browser); the harness installs stubs on globalThis so the shipped code
// runs unmodified. Each case sets its own stubs via make(); the originals are
// restored after the suite so Node's real global fetch is not left overwritten.
const { confirmDuplicateSends } = require('../public/js/duplicate.mjs');
const ORIG_FETCH = globalThis.fetch, ORIG_CONFIRM = globalThis.confirm;
test.after(() => { globalThis.fetch = ORIG_FETCH; globalThis.confirm = ORIG_CONFIRM; });
const make = (fetchFn, confirmFn) => { globalThis.fetch = fetchFn; globalThis.confirm = confirmFn; return confirmDuplicateSends; };

test('all recipient checks are in flight at once (parallel, not serial)', async () => {
  let inFlight = 0, maxInFlight = 0;
  const fetchFn = async () => {
    inFlight++; maxInFlight = Math.max(maxInFlight, inFlight);
    await new Promise((r) => setTimeout(r, 5));
    inFlight--;
    return { ok: true, json: async () => ({ sends: [{ date: '2026-01-01T00:00:00Z', letterId: 'ltr_x' }] }) };
  };
  let confirmMsg = null;
  const fn = make(fetchFn, (msg) => { confirmMsg = msg; return true; });
  const rs = Array.from({ length: 5 }, (_, i) => ({ name: 'R' + i }));
  const proceed = await fn(rs, rs.map((_, i) => 'f' + i));
  assert.strictEqual(maxInFlight, 5, 'a serial loop would peak at 1; parallel peaks at N');
  assert.strictEqual(proceed, true, 'confirm returned true -> proceed');
  assert.match(confirmMsg, /Possible duplicate send/);
});

test('no prior sends -> returns true WITHOUT prompting', async () => {
  let confirmCalled = false;
  const fetchFn = async () => ({ ok: true, json: async () => ({ sends: [] }) });
  const fn = make(fetchFn, () => { confirmCalled = true; return false; });
  const proceed = await fn([{ name: 'A' }], ['f0']);
  assert.strictEqual(proceed, true);
  assert.strictEqual(confirmCalled, false, 'no hits means no confirmation dialog');
});

test('a failed check never blocks the send', async () => {
  const fetchFn = async () => { throw new Error('network down'); };
  const fn = make(fetchFn, () => { throw new Error('confirm must not be called'); });
  const proceed = await fn([{ name: 'A' }, { name: 'B' }], ['f0', 'f1']);
  assert.strictEqual(proceed, true, 'a check error is swallowed and the send proceeds');
});

test('hits stay in recipient order even when later checks resolve first', async () => {
  const fetchFn = async (url) => {
    const i = Number(decodeURIComponent(url.split('fingerprint=')[1]).slice(1));
    await new Promise((r) => setTimeout(r, (5 - i))); // later recipients resolve sooner
    return { ok: true, json: async () => ({ sends: [{ date: '2026-01-01T00:00:00Z', letterId: 'ltr_' + i }] }) };
  };
  let msg = null;
  const fn = make(fetchFn, (m) => { msg = m; return true; });
  await fn([{ name: 'A' }, { name: 'B' }, { name: 'C' }], ['f0', 'f1', 'f2']);
  assert.ok(msg.indexOf('ltr_0') < msg.indexOf('ltr_1'), 'recipient A before B');
  assert.ok(msg.indexOf('ltr_1') < msg.indexOf('ltr_2'), 'recipient B before C');
});
