'use strict';
// Item 7: a STREAMED (non-audited) proxy response is byte-capped with
// backpressure, and an AUDITED (buffered) response is bounded by the SAME cap
// (fail-safe 502 instead of unbounded buffering). Both are exercised against a
// stub upstream. IMPORTANT: nothing at file scope may require lib/config (directly
// or via lib/proxy/server.js), because LOB_UPSTREAM is snapshotted when config
// first loads; PD_LOB_UPSTREAM must be set in test.before BEFORE server.js is
// required, or the proxy silently targets the real api.lob.com. The pure
// byteCapTransform unit tests live in byte-cap.test.js for exactly this reason.
const STREAM_CAP = 4096;
process.env.PD_PROXY_STREAM_MAX_BYTES = String(STREAM_CAP);
process.env.PD_SECRET = 'stream-cap-secret-fixed-0123456789ab';
process.env.PD_USERNAME = 'stream-user';
process.env.PD_PASSWORD = 'stream-pass-1234';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

let upstream, server, port, dataDir;

// Stream far more than the cap, in chunks, honoring backpressure. Guards against
// the proxy tearing the connection down mid-stream (which it does on a cap trip):
// without an 'error' listener the resulting socket error would be unhandled.
function streamOverCap(res) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  const total = STREAM_CAP * 4;
  const chunk = Buffer.alloc(1024, 0x61);
  let sent = 0;
  const pump = () => {
    while (sent < total) {
      sent += chunk.length;
      if (!res.write(chunk)) { res.once('drain', pump); return; }
    }
    res.end();
  };
  res.on('error', () => { /* client (proxy) went away mid-stream: expected */ });
  pump();
}

test.before(() => new Promise((resolve) => {
  upstream = http.createServer((req, res) => {
    req.on('error', () => { /* ignore */ });
    // GET /v1/letters is a non-audited call: it takes the streamed path.
    if (req.method === 'GET' && req.url.indexOf('/v1/letters') === 0) { streamOverCap(res); return; }
    // POST /v1/us_verifications is an AUDITED call: it takes the buffered path.
    // Streaming past the cap must make the proxy refuse (502), not buffer forever.
    if (req.method === 'POST' && req.url.indexOf('/v1/us_verifications') === 0) {
      req.resume();
      req.on('end', () => streamOverCap(res));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{}');
  });
  upstream.listen(0, '127.0.0.1', () => {
    // Set the upstream target BEFORE the first require of server.js (which loads
    // lib/config and snapshots LOB_UPSTREAM). This file requires nothing that
    // loads config at file scope, so this is the first load.
    process.env.PD_LOB_UPSTREAM = 'http://127.0.0.1:' + upstream.address().port;
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-streamcap-'));
    process.env.PD_DATA_DIR = dataDir;
    server = require('../server.js').server;
    server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
  });
}));

test.after(() => new Promise((resolve) => server.close(() => upstream.close(resolve))));

function login() {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, path: '/login', method: 'POST', agent: false,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, (res) => {
      res.resume();
      resolve(String(res.headers['set-cookie']).split(';')[0]);
    });
    r.on('error', reject);
    r.end('username=stream-user&password=stream-pass-1234');
  });
}

test('a streamed response larger than the cap is truncated (cap fires end-to-end)', async () => {
  const cookie = await login();
  const received = await new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, path: '/api/lob/v1/letters?limit=100', method: 'GET',
      agent: false, headers: { Cookie: cookie } }, (res) => {
      let bytes = 0;
      res.on('data', (c) => { bytes += c.length; });
      res.on('end', () => resolve(bytes));
      res.on('aborted', () => resolve(bytes));
      res.on('error', () => resolve(bytes));
    });
    r.on('error', reject);
    r.end();
  });
  // The stub offered STREAM_CAP*4 bytes; the cap must cut the client off near the
  // cap. The lower bound also proves the STUB was actually streamed (a real-Lob
  // error would be a few hundred bytes, far below the cap), guarding the wiring.
  assert.ok(received >= STREAM_CAP - 1024, 'client received roughly the cap, proving a real over-cap stream (got ' + received + ')');
  assert.ok(received <= STREAM_CAP * 2, 'client did not receive the whole over-cap stream (got ' + received + ')');
});

test('an audited response larger than the cap is refused with 502 and NOT captured', async () => {
  const cookie = await login();
  const r = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path: '/api/lob/v1/us_verifications', method: 'POST',
      agent: false, headers: { Cookie: cookie, 'Content-Type': 'application/json' } }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
      res.on('error', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end(JSON.stringify({ primary_line: '1 Main St', city: 'NYC', state: 'NY', zip_code: '10001' }));
  });
  assert.strictEqual(r.status, 502, 'over-cap audited response is refused, not buffered unbounded');
  // The bounded buffer refuses BEFORE capturing, so no address.verify line is
  // written: a malformed multi-megabyte "response" never enters the durable log.
  let log = '';
  try { log = fs.readFileSync(path.join(dataDir, 'audit.log'), 'utf8'); } catch (e) { /* no log yet: fine */ }
  assert.ok(!/"type":"address\.verify"/.test(log), 'the over-cap response must not be captured to the audit log');
});
