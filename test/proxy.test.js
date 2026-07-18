'use strict';
// Integration tests for the Lob reverse proxy against a REAL stub upstream.
// The stub is started first, then PD_LOB_UPSTREAM points the proxy at it, then
// server.js is required (the upstream target is resolved at module load). This
// exercises the app's core data path — header scrubbing, server-key injection,
// body forwarding, status/Content-Type passthrough, and the 502 error path —
// none of which the unit tests could reach.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

let upstream, upstreamPort, captured = null;
let server, port;

test.before(() => new Promise((resolve) => {
  upstream = http.createServer((req, res) => {
    // A path containing 'boom' simulates an upstream that drops the connection,
    // so the proxy's error path (502) can be exercised.
    if (req.url.indexOf('boom') !== -1) { req.socket.destroy(); return; }
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      captured = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) };
      res.writeHead(201, { 'Content-Type': 'application/json; charset=utf-8', 'X-Upstream-Only': 'secret' });
      res.end(JSON.stringify({ id: 'ltr_stub', ok: true }));
    });
  });
  upstream.listen(0, '127.0.0.1', () => {
    upstreamPort = upstream.address().port;
    process.env.PD_LOB_UPSTREAM = 'http://127.0.0.1:' + upstreamPort;
    process.env.PD_LOB_KEY = 'test_stubkey';
    process.env.PD_SECRET = 'proxy-itest-secret-fixed';
    process.env.PD_USERNAME = 'itest-user';
    process.env.PD_PASSWORD = 'itest-pass';
    // POST /v1/letters is now an audited call (item 1): point the store at a
    // temp dir so this suite never writes into the repo's default ./data.
    process.env.PD_DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-proxy-'));
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
    'username=itest-user&password=itest-pass'
  );
  return String(r.headers['set-cookie']).split(';')[0];
}

test('proxy scrubs sensitive headers and injects the server key upstream', async () => {
  const cookie = await login();
  captured = null;
  const r = await request({
    path: '/api/lob/v1/letters?limit=3',
    method: 'GET',
    headers: { Cookie: cookie, Origin: 'https://evil.example', Referer: 'https://evil.example/x', 'Accept-Encoding': 'gzip' },
  });
  // Upstream saw the request with the sensitive headers stripped...
  assert.ok(captured, 'upstream received the proxied request');
  assert.strictEqual(captured.url, '/v1/letters?limit=3', 'path prefix stripped, query preserved');
  assert.strictEqual(captured.headers.cookie, undefined, 'session cookie NOT forwarded to Lob');
  assert.strictEqual(captured.headers.origin, undefined, 'origin stripped');
  assert.strictEqual(captured.headers.referer, undefined, 'referer stripped');
  assert.strictEqual(captured.headers['accept-encoding'], undefined, 'accept-encoding stripped');
  // ...and with the server key injected as Basic auth (key:'' base64).
  const expected = 'Basic ' + Buffer.from('test_stubkey:').toString('base64');
  assert.strictEqual(captured.headers.authorization, expected, 'PD_LOB_KEY injected as Basic auth');
  // Client got the upstream status + content-type back.
  assert.strictEqual(r.status, 201, 'upstream status passed through');
  assert.match(r.headers['content-type'], /application\/json/, 'upstream Content-Type passed through');
  assert.match(r.body, /ltr_stub/, 'upstream body passed through');
});

test('proxy forwards the request body verbatim', async () => {
  const cookie = await login();
  captured = null;
  const payload = JSON.stringify({ hello: 'world', n: 42 });
  await request(
    { path: '/api/lob/v1/us_verifications', method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' } },
    payload
  );
  assert.strictEqual(captured.method, 'POST');
  assert.strictEqual(captured.body.toString(), payload, 'body reached upstream unchanged');
});

test('a client-supplied Authorization header overrides the injected server key', async () => {
  const cookie = await login();
  captured = null;
  const clientAuth = 'Basic ' + Buffer.from('live_pasted:').toString('base64');
  await request({
    path: '/api/lob/v1/letters',
    method: 'GET',
    headers: { Cookie: cookie, Authorization: clientAuth },
  });
  assert.strictEqual(captured.headers.authorization, clientAuth, 'pasted key wins over PD_LOB_KEY');
});

test('security headers survive on the proxied response', async () => {
  const cookie = await login();
  const r = await request({ path: '/api/lob/v1/letters', method: 'GET', headers: { Cookie: cookie } });
  assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
  assert.strictEqual(r.headers['x-frame-options'], 'DENY');
  assert.ok(r.headers['content-security-policy'], 'CSP present on proxy response');
  assert.strictEqual(r.headers['x-upstream-only'], undefined, 'upstream-only headers are NOT forwarded to the client');
});

test('upstream failure yields a generic 502 with no internal detail leaked', async () => {
  const cookie = await login();
  // Use an ALLOWLISTED path that still trips the stub's connection-drop (its id
  // contains "boom"), so this exercises the 502 path rather than the 404 gate.
  const r = await request({ path: '/api/lob/v1/letters/ltr_boom', method: 'GET', headers: { Cookie: cookie } });
  assert.strictEqual(r.status, 502);
  const body = JSON.parse(r.body);
  assert.strictEqual(body.error.message, 'Upstream request failed');
  assert.ok(!/127\.0\.0\.1|ECONNRESET|socket/i.test(r.body), 'no upstream internals leaked to the client');
});

test('proxy allowlist: disallowed method+path is 404 locally and NEVER forwarded upstream', async () => {
  const cookie = await login();
  // Money-moving / financial endpoints the app never uses, plus a wrong method
  // and a malformed letter id. Each must be answered 404 without the stub
  // upstream ever seeing the request.
  const disallowed = [
    { path: '/api/lob/v1/checks', method: 'GET' },
    { path: '/api/lob/v1/checks', method: 'POST' },
    { path: '/api/lob/v1/bank_accounts', method: 'GET' },
    { path: '/api/lob/v1/bank_accounts', method: 'POST' },
    { path: '/api/lob/v1/postcards', method: 'POST' },
    { path: '/api/lob/v1/letters', method: 'PUT' },             // wrong method on an allowed path
    { path: '/api/lob/v1/letters', method: 'DELETE' },          // cancel needs an id
    { path: '/api/lob/v1/letters/not-an-id', method: 'GET' },   // id must be ltr_<alnum>
    { path: '/api/lob/v1/us_verifications', method: 'GET' },    // verify is POST-only
    { path: '/api/lob/v1/checks?x=/v1/letters', method: 'GET' }, // query cannot smuggle an allowed path
  ];
  for (const d of disallowed) {
    captured = null;
    const r = await request({ path: d.path, method: d.method, headers: { Cookie: cookie } });
    assert.strictEqual(r.status, 404, d.method + ' ' + d.path + ' must be 404');
    assert.strictEqual(captured, null, d.method + ' ' + d.path + ' must NOT reach upstream');
  }
});

test('proxy allowlist: DELETE of a well-formed letter id is forwarded (cancel)', async () => {
  const cookie = await login();
  captured = null;
  const r = await request({ path: '/api/lob/v1/letters/ltr_abc123', method: 'DELETE', headers: { Cookie: cookie } });
  assert.ok(captured, 'cancel reached upstream');
  assert.strictEqual(captured.method, 'DELETE');
  assert.strictEqual(captured.url, '/v1/letters/ltr_abc123');
  assert.strictEqual(r.status, 201, 'stub upstream status passed through');
});
