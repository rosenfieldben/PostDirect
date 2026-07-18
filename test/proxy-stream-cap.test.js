'use strict';
// Item 7: a STREAMED (non-audited) proxy response is byte-capped with
// backpressure. Two levels of coverage: byteCapTransform in isolation, and the
// cap wired into the live proxy against a stub that streams past the cap. The
// small cap is set via PD_PROXY_STREAM_MAX_BYTES before server.js is required.
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
const { pipeline, Readable, Writable } = require('node:stream');
const { byteCapTransform } = require('../lib/proxy');

// ── byteCapTransform in isolation ──
function runCap(chunks, cap) {
  return new Promise((resolve) => {
    let bytes = 0;
    const sink = new Writable({ write(c, e, cb) { bytes += c.length; cb(); } });
    pipeline(Readable.from(chunks), byteCapTransform(cap), sink, (err) => resolve({ err: err || null, bytes }));
  });
}

test('byteCapTransform forwards everything when under the cap', async () => {
  const { err, bytes } = await runCap([Buffer.alloc(1000), Buffer.alloc(1000)], 4096);
  assert.strictEqual(err, null, 'no error under the cap');
  assert.strictEqual(bytes, 2000, 'all bytes forwarded');
});

test('byteCapTransform errors (and tears down) once the running total exceeds the cap', async () => {
  const { err, bytes } = await runCap([Buffer.alloc(2000), Buffer.alloc(2000), Buffer.alloc(2000)], 4096);
  assert.ok(err instanceof Error, 'over-cap stream errors');
  assert.match(err.message, /exceeded 4096 bytes/);
  assert.ok(bytes < 6000, 'the over-cap chunk is not forwarded (got ' + bytes + ')');
});

// ── The cap wired into the live proxy ──
let upstream, server, port;

test.before(() => new Promise((resolve) => {
  upstream = http.createServer((req, res) => {
    // GET /v1/letters is a non-audited call: it takes the streamed path. Stream
    // far more than the cap so the proxy's byteCapTransform must trip.
    if (req.method === 'GET' && req.url.indexOf('/v1/letters') === 0) {
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
      pump();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{}');
  });
  upstream.listen(0, '127.0.0.1', () => {
    process.env.PD_LOB_UPSTREAM = 'http://127.0.0.1:' + upstream.address().port;
    process.env.PD_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-streamcap-'));
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
  // The upstream offered STREAM_CAP*4 bytes; the cap must cut the client off well
  // before that. Allow generous slack for chunk/buffer boundaries.
  assert.ok(received < STREAM_CAP * 4, 'client must not receive the full over-cap body (got ' + received + ')');
  assert.ok(received <= STREAM_CAP * 2, 'client received roughly the cap, not the whole stream (got ' + received + ')');
});
