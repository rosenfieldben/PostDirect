'use strict';
// Server-side Lob key (PD_LOB_KEY) behavior. This file runs in its own
// process (node --test isolates test files), so setting PD_LOB_KEY here
// before requiring server.js cannot leak into the other suites — routes.test.js
// covers the PD_LOB_KEY-unset shape of /api/config.
process.env.PD_LOB_KEY = 'test_srvkey_abc123';
process.env.PD_SECRET = 'srvkey-secret-fixed-value';
process.env.PD_USERNAME = 'srvkey-user';
process.env.PD_PASSWORD = 'srvkey-pass';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { server, lobAuthorization, lobKeyEnv } = require('../server.js');

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

test('lobAuthorization: mints Basic auth from PD_LOB_KEY when the client sent none', () => {
  const expected = 'Basic ' + Buffer.from('test_srvkey_abc123:').toString('base64');
  assert.strictEqual(lobAuthorization(undefined), expected);
  assert.strictEqual(lobAuthorization(''), expected);
});

test('lobAuthorization: a client-supplied header always wins over the server key', () => {
  const clientAuth = 'Basic ' + Buffer.from('live_pasted_override:').toString('base64');
  assert.strictEqual(lobAuthorization(clientAuth), clientAuth);
});

test('lobKeyEnv: classifies test_/live_ and — critically — errs an UNRECOGNIZED key toward live', () => {
  assert.strictEqual(lobKeyEnv('test_abc'), 'test');
  assert.strictEqual(lobKeyEnv('live_abc'), 'live');
  // The safety-critical branch: a key that does not start with test_ must be
  // reported as 'live' so the UI never shows a reassuring "Test" badge for a
  // key that actually spends postage.
  assert.strictEqual(lobKeyEnv('xyz_garbage'), 'live');
  assert.strictEqual(lobKeyEnv('  live_trimmed  '), 'live');
  assert.strictEqual(lobKeyEnv(''), null);
  assert.strictEqual(lobKeyEnv(null), null);
});

test('/api/config reports the server key and its environment (never the key itself)', async () => {
  const login = await request(
    { path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    new URLSearchParams({ username: 'srvkey-user', password: 'srvkey-pass' }).toString()
  );
  assert.strictEqual(login.status, 302);
  const cookie = String(login.headers['set-cookie']).split(';')[0];

  const r = await request({ path: '/api/config', method: 'GET', headers: { Cookie: cookie } });
  assert.strictEqual(r.status, 200);
  assert.deepStrictEqual(JSON.parse(r.body), { server_key: true, env: 'test' });
  assert.ok(!r.body.includes('srvkey_abc123'), 'the key value must never reach the browser');
});
