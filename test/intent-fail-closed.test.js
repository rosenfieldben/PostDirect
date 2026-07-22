'use strict';
// Item 2: the write-ahead intent must fail CLOSED. If the durable intent record
// cannot be written, the proxy must answer 503 and NEVER contact Lob: a send we
// cannot record is a send we refuse to make. This test forces the intent write
// to fail by making PD_DATA_DIR/audit.log a DIRECTORY, so the append's open()
// raises EISDIR. That works as any uid (root included), unlike a chmod-based
// trick which root would bypass. The stub records whether it was ever hit; the
// assertion is that it was not.
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const test = require('node:test');
const assert = require('node:assert');

let upstream, upstreamPort, stubHits = 0;
let server, port, DATA_DIR;

test.before(() => new Promise((resolve) => {
  upstream = http.createServer((req, res) => {
    stubHits += 1; // any contact at all is a failure of the fail-closed guarantee
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: 'ltr_shouldnothappen', object: 'letter' }));
  });
  upstream.listen(0, '127.0.0.1', () => {
    upstreamPort = upstream.address().port;
    DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-failclosed-'));
    process.env.PD_LOB_UPSTREAM = 'http://127.0.0.1:' + upstreamPort;
    process.env.PD_DATA_DIR = DATA_DIR;
    process.env.PD_SECRET = 'failclosed-itest-secret-fixed-0123456789';
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

test('an unwritable intent record refuses the send with 503 and never contacts Lob', async () => {
  const cookie = await login();
  // Make the audit log unwritable: replace the (not-yet-created) audit.log path
  // with a directory, so the intent append's open(..., "a") raises EISDIR.
  fs.mkdirSync(path.join(DATA_DIR, 'audit.log'));

  stubHits = 0;
  const r = await request({
    path: '/api/lob/v1/letters', method: 'POST',
    headers: { Authorization: 'Basic ' + Buffer.from('test_k:').toString('base64'), Cookie: cookie,
      'Content-Type': 'multipart/form-data; boundary=x' },
  }, 'RAW-MULTIPART-BODY');

  assert.strictEqual(r.status, 503, 'the send is refused when the record cannot be written');
  assert.match(r.body, /durable record could not be written/, 'the client is told why');
  assert.strictEqual(stubHits, 0, 'Lob was NEVER contacted: we failed closed BEFORE the upstream request');
});
