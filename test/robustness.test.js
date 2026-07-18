'use strict';
// Regression tests for the crash-guard and lockout fixes. A dedicated listening
// server (with its own rate-limit buckets) so these don't perturb routes.test.js.
process.env.PD_SECRET = 'robust-itest-secret-fixed';
process.env.PD_USERNAME = 'itest-user';
process.env.PD_PASSWORD = 'itest-pass';
// Trust XFF so each sub-test can present a distinct, isolated client IP.
process.env.PD_TRUST_PROXY = '1';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const net = require('node:net');
const { server, loginFailureDelay } = require('../server.js');

// Neutralize the progressive failure delay: these tests assert lockout and
// anti-lockout status codes, not timing (failure-throttle.test.js covers the
// schedule), so they must not sleep through the real one.
loginFailureDelay.sleep = async () => {};

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

// Send a raw request line + headers over a bare socket so we can present an
// invalid Host value the high-level http client would reject before sending.
function raw(rawBytes) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(rawBytes));
    let buf = '';
    sock.on('data', (d) => { buf += d.toString(); });
    sock.on('end', () => resolve(buf));
    sock.on('close', () => resolve(buf));
    sock.on('error', reject);
    setTimeout(() => { try { sock.destroy(); } catch (e) {} resolve(buf); }, 1500);
  });
}

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };
const loginBody = (u, p) => new URLSearchParams({ username: u, password: p }).toString();

test('malformed Host header returns 400 and does NOT crash the process', async () => {
  for (const host of ['a b c', 'a:b', '[bad']) {
    const resp = await raw('GET / HTTP/1.1\r\nHost: ' + host + '\r\nConnection: close\r\n\r\n');
    assert.match(resp.split('\r\n')[0], /400/, 'malformed Host "' + host + '" => 400 (got: ' + resp.split('\r\n')[0] + ')');
  }
  // The process is still up: a normal request is served right after.
  const ok = await request({ path: '/login', method: 'GET' });
  assert.strictEqual(ok.status, 200, 'server still serving after malformed-Host requests');
});

test('IP lockout does NOT deny a correct password (fix for shared-IP collateral lockout)', async () => {
  const IP = '203.0.113.7'; // isolated from other tests' buckets
  // Fill the per-IP bucket with 5 failures from this single IP.
  for (let i = 1; i <= 5; i++) {
    const r = await request({ path: '/login', method: 'POST', headers: { ...FORM, 'X-Forwarded-For': IP } }, loginBody('itest-user', 'wrong-' + i));
    assert.strictEqual(r.status, i < 5 ? 401 : 429, 'attempt ' + i);
  }
  // A further wrong attempt from that IP is throttled...
  const blocked = await request({ path: '/login', method: 'POST', headers: { ...FORM, 'X-Forwarded-For': IP } }, loginBody('itest-user', 'still-wrong'));
  assert.strictEqual(blocked.status, 429, 'wrong password from a blocked IP stays 429');
  // ...but the CORRECT password from the very same blocked IP still logs in.
  const ok = await request({ path: '/login', method: 'POST', headers: { ...FORM, 'X-Forwarded-For': IP } }, loginBody('itest-user', 'itest-pass'));
  assert.strictEqual(ok.status, 302, 'correct password succeeds despite a full per-IP bucket');
  assert.ok(String(ok.headers['set-cookie']).includes('pd_session='), 'session cookie issued');
});
