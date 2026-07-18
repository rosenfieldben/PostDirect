'use strict';
// Progressive failure delay + global failure throttle. Env is set before
// requiring server.js (credentials are read at module load); PD_TRUST_PROXY
// lets each sub-test forge a distinct client IP so bucket keys are isolated.
process.env.PD_SECRET = 'throttle-itest-secret-fixed';
process.env.PD_USERNAME = 'itest-user';
process.env.PD_PASSWORD = 'itest-pass';
process.env.PD_TRUST_PROXY = '1';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { server, loginThrottleDecision, loginFailureDelay } = require('../server.js');

const WINDOW_MS = 15 * 60 * 1000;

// ── Unit: the pure decision function, driven by an injected clock ──

test('a correct password is always allowed, undelayed, even with the global window tripped', () => {
  const t = 1_000_000;
  const tripped = { count: 999, first: t };
  const d = loginThrottleDecision('ok', tripped, 42, t);
  assert.strictEqual(d.action, 'allow');
  assert.strictEqual(d.delayMs, 0);
  assert.strictEqual(d.global, tripped, 'success does not touch the global failure window');
});

test('failure delay grows with consecutive failures for the key and caps at 4s', () => {
  const t = 1_000_000;
  const expected = [0, 500, 1000, 2000, 4000, 4000, 4000]; // schedule, then the cap
  let global = { count: 0, first: 0 };
  expected.forEach((ms, i) => {
    const d = loginThrottleDecision('fail', global, i + 1, t + i);
    assert.strictEqual(d.action, 'delay', 'attempt ' + (i + 1));
    assert.strictEqual(d.delayMs, ms, 'attempt ' + (i + 1) + ' delay');
    global = d.global;
  });
  assert.strictEqual(global.count, expected.length, 'each failure counts against the global window');
  assert.strictEqual(global.first, t, 'window anchored at the first failure');
});

test('the global ceiling throttles further failures uniformly, regardless of key', () => {
  const t = 1_000_000;
  let global = { count: 0, first: 0 };
  for (let i = 0; i < 50; i++) global = loginThrottleDecision('fail', global, 1, t + i).global;
  assert.strictEqual(global.count, 50);
  // Once tripped: fast 429 for a brand-new key (keyFailures 1) and for a
  // hammered key alike, with no delay an attacker could pin sockets with.
  for (const keyFailures of [1, 3, 100]) {
    const d = loginThrottleDecision('fail', global, keyFailures, t + 60);
    assert.strictEqual(d.action, 'throttle', 'keyFailures=' + keyFailures);
    assert.strictEqual(d.delayMs, 0, 'throttled rejections are fast');
    assert.strictEqual(d.global.count, 50, 'throttled attempts do not extend the window');
  }
});

test('the global window expires and failures are delayed (not throttled) again', () => {
  const t = 1_000_000;
  let global = { count: 50, first: t };
  // Just inside the window: still throttled.
  assert.strictEqual(loginThrottleDecision('fail', global, 1, t + WINDOW_MS).action, 'throttle');
  // Just past it: the window resets and this failure starts a new one.
  const d = loginThrottleDecision('fail', global, 1, t + WINDOW_MS + 1);
  assert.strictEqual(d.action, 'delay');
  assert.strictEqual(d.global.count, 1, 'expired window restarts the count');
  assert.strictEqual(d.global.first, t + WINDOW_MS + 1, 'new window anchored now');
});

// ── Integration: the login route applies the decision (sleep stubbed, so
// requested delays are observed without this suite ever actually sleeping) ──

const requestedDelays = [];
loginFailureDelay.sleep = async (ms) => { requestedDelays.push(ms); };

let port;
test.before(() => new Promise((resolve) => {
  server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
}));
test.after(() => new Promise((resolve) => server.close(resolve)));

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, agent: false, ...opts }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const loginBody = (u, p) => new URLSearchParams({ username: u, password: p }).toString();
const attempt = (user, pass, ip) =>
  request({ path: '/login', method: 'POST', headers: { ...FORM, 'X-Forwarded-For': ip } }, loginBody(user, pass));

test('consecutive wrong guesses from one key are delayed per the schedule', async () => {
  requestedDelays.length = 0;
  for (let i = 1; i <= 4; i++) {
    const r = await attempt('delay-user', 'wrong-' + i, '198.51.100.1');
    assert.strictEqual(r.status, 401, 'attempt ' + i);
  }
  // The first failure answers immediately (no sleep call), then the schedule.
  assert.deepStrictEqual(requestedDelays, [500, 1000, 2000]);
});

test('a correct password mid-flood is never delayed', async () => {
  requestedDelays.length = 0;
  const ok = await attempt('itest-user', 'itest-pass', '198.51.100.1');
  assert.strictEqual(ok.status, 302, 'correct password succeeds from the flooded IP');
  assert.deepStrictEqual(requestedDelays, [], 'no delay was requested for the success');
});

// Deliberately LAST in this file: tripping the process-wide ceiling makes
// every later failed attempt in this process answer 429.
test('a flood across many distinct keys trips the global ceiling', async () => {
  // Every attempt uses a fresh IP and username (fresh bucket keys), so only
  // the global window can stop the flood. Bounded loop: earlier tests in this
  // file already consumed part of the ceiling.
  let tripped = false;
  for (let i = 0; i < 60 && !tripped; i++) {
    const r = await attempt('spray-user-' + i, 'wrong', '203.0.113.' + (100 + i));
    if (r.status === 429) tripped = true;
    else assert.strictEqual(r.status, 401, 'pre-trip attempt ' + i);
  }
  assert.ok(tripped, 'the global ceiling tripped within the bound');

  // Uniform once tripped: yet another brand-new key is rejected, fast.
  requestedDelays.length = 0;
  const fresh = await attempt('another-new-user', 'wrong', '198.18.7.7');
  assert.strictEqual(fresh.status, 429, 'fresh key is throttled once the ceiling is hit');
  assert.deepStrictEqual(requestedDelays, [], 'throttled rejection requested no delay');

  // The anti-lockout property survives the tripped ceiling.
  const owner = await attempt('itest-user', 'itest-pass', '198.18.9.9');
  assert.strictEqual(owner.status, 302, 'correct password still logs in mid-flood');
});
