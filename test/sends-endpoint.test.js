'use strict';
// Item 3, server side: GET /api/sends?fingerprint= (the duplicate-warning
// source) and findSendsByFingerprint. A temp PD_DATA_DIR is set before
// requiring server.js.
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const test = require('node:test');
const assert = require('node:assert');

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-sends-'));
process.env.PD_DATA_DIR = DATA_DIR;
process.env.PD_SECRET = 'sends-itest-secret-fixed-0123456789';
process.env.PD_USERNAME = 'itest-user';
process.env.PD_PASSWORD = 'itest-password';
const store = require('../server.js');

const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);

test('findSendsByFingerprint returns only successful creates for that fingerprint', () => {
  const lines = [
    { ts: '2026-07-01T00:00:00Z', type: 'letter.create', status: 200, letterId: 'ltr_1', keyEnv: 'live', fingerprint: FP_A },
    { ts: '2026-07-02T00:00:00Z', type: 'letter.create', status: 422, letterId: null, keyEnv: 'live', fingerprint: FP_A }, // failed: excluded
    { ts: '2026-07-03T00:00:00Z', type: 'letter.create', status: 200, letterId: 'ltr_2', keyEnv: 'test', fingerprint: FP_A },
    { ts: '2026-07-04T00:00:00Z', type: 'letter.create', status: 200, letterId: 'ltr_3', keyEnv: 'live', fingerprint: FP_B }, // other fp
    { ts: '2026-07-05T00:00:00Z', type: 'address.verify', status: 200, fingerprint: FP_A }, // wrong type
  ];
  const hits = store.findSendsByFingerprint(lines, FP_A);
  assert.deepStrictEqual(hits, [
    { date: '2026-07-01T00:00:00Z', letterId: 'ltr_1', keyEnv: 'live' },
    { date: '2026-07-03T00:00:00Z', letterId: 'ltr_2', keyEnv: 'test' },
  ]);
  assert.deepStrictEqual(store.findSendsByFingerprint(lines, 'c'.repeat(64)), []);
});

let server, port;
test.before(() => new Promise((resolve) => {
  server = store.server;
  server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
}));
test.after(() => new Promise((resolve) => server.close(resolve)));

function request(opts) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, agent: false, ...opts }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject);
    r.end();
  });
}
async function login() {
  const r = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, agent: false, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, (res) => { res.resume(); res.on('end', () => resolve(res)); });
    req.on('error', reject); req.write('username=itest-user&password=itest-password'); req.end();
  });
  return String(r.headers['set-cookie']).split(';')[0];
}

test('GET /api/sends requires a session', async () => {
  const r = await request({ path: '/api/sends?fingerprint=' + FP_A, method: 'GET' });
  assert.strictEqual(r.status, 302);
  assert.strictEqual(r.headers.location, '/login');
});

test('GET /api/sends rejects a malformed fingerprint with 400', async () => {
  const cookie = await login();
  for (const bad of ['', 'xyz', 'A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65)]) {
    const r = await request({ path: '/api/sends?fingerprint=' + encodeURIComponent(bad), method: 'GET', headers: { Cookie: cookie } });
    assert.strictEqual(r.status, 400, JSON.stringify(bad) + ' must be 400');
  }
});

test('GET /api/sends returns the seeded matches for a fingerprint', async () => {
  // Seed the store the endpoint reads.
  store.auditAppend(DATA_DIR, { type: 'letter.create', status: 200, letterId: 'ltr_seed1', keyEnv: 'live', fingerprint: FP_A });
  store.auditAppend(DATA_DIR, { type: 'letter.create', status: 200, letterId: 'ltr_seed2', keyEnv: 'live', fingerprint: FP_A });
  const cookie = await login();
  const r = await request({ path: '/api/sends?fingerprint=' + FP_A, method: 'GET', headers: { Cookie: cookie } });
  assert.strictEqual(r.status, 200);
  const body = JSON.parse(r.body);
  assert.strictEqual(body.sends.length, 2);
  assert.strictEqual(body.sends[0].letterId, 'ltr_seed1');
  assert.strictEqual(body.sends[1].letterId, 'ltr_seed2');
  // No matches for an unseen fingerprint.
  const none = await request({ path: '/api/sends?fingerprint=' + FP_B, method: 'GET', headers: { Cookie: cookie } });
  assert.deepStrictEqual(JSON.parse(none.body).sends, []);
});
