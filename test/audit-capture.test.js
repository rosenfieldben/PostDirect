'use strict';
// Integration test for item 1: capture happens IN THE PROXY against a real stub
// upstream, writing to a temp PD_DATA_DIR. The stub, the data dir, and all
// credentials/upstream are set BEFORE requiring server.js (resolved at load).
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const test = require('node:test');
const assert = require('node:assert');

let upstream, upstreamPort, lastCreateBody = null;
let server, port, DATA_DIR;

test.before(() => new Promise((resolve) => {
  upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      if (req.method === 'POST' && req.url === '/v1/letters') {
        lastCreateBody = body;
        // Echo an invalid-option 422 when the marker is present, else 200 OK.
        if (body.toString('latin1').indexOf('FORCE_422') !== -1) {
          res.writeHead(422, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'send_date is invalid' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'ltr_stub123', object: 'letter', to: { name: 'A' } }));
        return;
      }
      if (req.method === 'DELETE' && /^\/v1\/letters\/ltr_/.test(req.url)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'ltr_stub123', deleted: true }));
        return;
      }
      if (req.method === 'POST' && req.url === '/v1/us_verifications') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ deliverability: 'deliverable' }));
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'not found' } }));
    });
  });
  upstream.listen(0, '127.0.0.1', () => {
    upstreamPort = upstream.address().port;
    DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-capture-'));
    process.env.PD_LOB_UPSTREAM = 'http://127.0.0.1:' + upstreamPort;
    process.env.PD_DATA_DIR = DATA_DIR;
    process.env.PD_SECRET = 'capture-itest-secret-fixed-0123456789';
    process.env.PD_USERNAME = 'itest-user';
    process.env.PD_PASSWORD = 'itest-password';
    server = require('../server.js').server;
    server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
  });
}));

test.after(() => new Promise((resolve) => server.close(() => upstream.close(resolve))));

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, agent: false, ...opts }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

async function login() {
  const r = await request(
    { path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    'username=itest-user&password=itest-password'
  );
  return String(r.headers['set-cookie']).split(';')[0];
}

function readLog() {
  const store = require('../server.js');
  return store.auditReadLines(DATA_DIR);
}

const clientKeyHeader = { 'Authorization': 'Basic ' + Buffer.from('test_clientkey:').toString('base64') };

test('POST /v1/letters appends one letter.create with matching blob and no auth material', async () => {
  const cookie = await login();
  const multipart = 'RAW-MULTIPART-BODY-BYTES-primary';
  const before = readLog().length;
  const r = await request({
    path: '/api/lob/v1/letters', method: 'POST',
    headers: { ...clientKeyHeader, Cookie: cookie, 'Content-Type': 'multipart/form-data; boundary=x',
      'Idempotency-Key': 'idem-capture-1', 'X-PD-Fingerprint': 'a'.repeat(64) },
  }, multipart);
  assert.strictEqual(r.status, 200);
  assert.ok(r.body.includes('ltr_stub123'), 'client still receives the upstream response');

  const lines = readLog();
  assert.strictEqual(lines.length, before + 1, 'exactly one new line');
  const ev = lines[lines.length - 1];
  assert.strictEqual(ev.type, 'letter.create');
  assert.strictEqual(ev.status, 200);
  assert.strictEqual(ev.letterId, 'ltr_stub123');
  assert.strictEqual(ev.idempotencyKey, 'idem-capture-1');
  assert.strictEqual(ev.fingerprint, 'a'.repeat(64));
  assert.strictEqual(ev.keyEnv, 'test', 'derived from the client key, which is never stored');

  const store = require('../server.js');
  const blob = store.readBlob(DATA_DIR, ev.requestBlobSha256);
  assert.strictEqual(blob.toString(), multipart, 'blob holds exactly the bytes the stub received');
  assert.strictEqual(store.sha256Hex(Buffer.concat([Buffer.from(multipart)])), ev.requestBlobSha256);
  assert.deepStrictEqual(lastCreateBody.toString(), multipart, 'stub received the same bytes');

  const serialized = fs.readFileSync(path.join(DATA_DIR, 'audit.log'), 'utf8');
  assert.ok(!serialized.includes('clientkey'), 'the Lob key never reaches the log');
});

test('a stub 422 still produces a letter.create event with status 422', async () => {
  const cookie = await login();
  const r = await request({
    path: '/api/lob/v1/letters', method: 'POST',
    headers: { ...clientKeyHeader, Cookie: cookie, 'Content-Type': 'multipart/form-data; boundary=x' },
  }, 'FORCE_422 body');
  assert.strictEqual(r.status, 422, 'the client sees the real upstream status');
  const ev = readLog().filter((l) => l.type === 'letter.create').pop();
  assert.strictEqual(ev.status, 422);
  assert.strictEqual(ev.letterId, null);
  assert.ok(ev.response.error, 'the 422 body is captured');
});

test('DELETE letter and POST verification are captured', async () => {
  const cookie = await login();
  const del = await request({ path: '/api/lob/v1/letters/ltr_stub123', method: 'DELETE', headers: { ...clientKeyHeader, Cookie: cookie } });
  assert.strictEqual(del.status, 200);
  const cancel = readLog().filter((l) => l.type === 'letter.cancel').pop();
  assert.strictEqual(cancel.letterId, 'ltr_stub123');
  assert.strictEqual(cancel.status, 200);

  const addr = { primary_line: '185 Berry St', secondary_line: 'Ste 6100', city: 'San Francisco', state: 'CA', zip_code: '94107' };
  const ver = await request({
    path: '/api/lob/v1/us_verifications', method: 'POST',
    headers: { ...clientKeyHeader, Cookie: cookie, 'Content-Type': 'application/json' },
  }, JSON.stringify(addr));
  assert.strictEqual(ver.status, 200);
  const verify = readLog().filter((l) => l.type === 'address.verify').pop();
  const store = require('../server.js');
  assert.strictEqual(verify.addressSha256,
    store.addressHash({ line1: '185 Berry St', line2: 'Ste 6100', city: 'San Francisco', state: 'CA', zip: '94107' }));
});

test('a plain GET listing through the proxy is NOT captured', async () => {
  const cookie = await login();
  const before = readLog().length;
  await request({ path: '/api/lob/v1/letters?limit=1', method: 'GET', headers: { ...clientKeyHeader, Cookie: cookie } });
  assert.strictEqual(readLog().length, before, 'reads are not audit events');
});
