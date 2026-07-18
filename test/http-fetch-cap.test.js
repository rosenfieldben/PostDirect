'use strict';
// Fix for review finding #7: httpGetBuffer (used by the proof export to fetch
// the rendered PDF and the letter object) caps the buffered response so a
// runaway or malformed asset cannot exhaust memory. Exercised against a local
// stub, no real network.
const http = require('node:http');

process.env.PD_SECRET = process.env.PD_SECRET || 'cap-secret-fixed-0123456789abcdef';
const test = require('node:test');
const assert = require('node:assert');
const store = require('../server.js');

let stub, stubPort;
test.before(() => new Promise((resolve) => {
  stub = http.createServer((req, res) => {
    // /big streams ~100 KB in 1 KB chunks; /small returns a short body.
    if (req.url === '/big') {
      res.writeHead(200, { 'Content-Type': 'application/pdf' });
      let n = 0;
      const chunk = Buffer.alloc(1024, 0x41);
      const iv = setInterval(() => {
        if (n++ >= 100) { clearInterval(iv); res.end(); return; }
        if (!res.write(chunk)) { /* backpressure: fine for a test */ }
      }, 1);
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/pdf' });
    res.end(Buffer.from('%PDF small body'));
  });
  stub.listen(0, '127.0.0.1', () => { stubPort = stub.address().port; resolve(); });
}));
test.after(() => new Promise((resolve) => stub.close(resolve)));

function target(path) {
  return { transport: http, hostname: '127.0.0.1', port: stubPort, path, headers: { host: '127.0.0.1' } };
}

test('httpGetBuffer returns an oversize error (status 0) when the response exceeds maxBytes', async () => {
  const r = await store.httpGetBuffer(target('/big'), 10 * 1024); // cap 10 KB, body ~100 KB
  assert.strictEqual(r.status, 0, 'no successful status for an oversize response');
  assert.match(r.error, /exceeded/, 'error explains the cap');
  assert.strictEqual(r.buffer.length, 0, 'no partial buffer is surfaced');
});

test('httpGetBuffer returns the body normally when it is under the cap', async () => {
  const r = await store.httpGetBuffer(target('/small'), 10 * 1024);
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.buffer.toString(), '%PDF small body');
});

test('a body under the default cap is not truncated', async () => {
  const r = await store.httpGetBuffer(target('/small')); // no explicit cap -> PROOF_FETCH_MAX_BYTES
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.buffer.toString(), '%PDF small body');
  assert.strictEqual(store.PROOF_FETCH_MAX_BYTES, 60 * 1024 * 1024, 'the default cap is 60 MB');
});
