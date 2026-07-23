'use strict';
// Item 2: when enforcement is ON but the origin has NO JWKS keys (it cannot reach
// the team's cert endpoint), enforced requests fail closed with 503 + Retry-After,
// not 403: the request might be legitimate and the outage is ours, so "try again"
// is the honest answer. Separate file so it boots a keyless server (the enforcer
// is a module singleton; a fresh process gives it a fresh, unprimed config).
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert');

const b64url = (x) => Buffer.from(x).toString('base64url');
const TEAM = 'faketeam.cloudflareaccess.com';
const ISSUER = 'https://' + TEAM;
const AUD = 'aud-p3c-503';

let jwksServer, keypair, server, port, DATA_DIR;

test.before(() => new Promise((resolve) => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  keypair = { privateKey, kid: 'never-served' };
  // A certs endpoint that always 500s: the client can never obtain a key, so it
  // stays keyless and every enforced request fails closed with 503.
  jwksServer = http.createServer((req, res) => { res.writeHead(500); res.end(); });
  jwksServer.listen(0, '127.0.0.1', () => {
    const jwksPort = jwksServer.address().port;
    DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-access503-'));
    process.env.PD_DATA_DIR = DATA_DIR;
    process.env.PD_SECRET = 'access503-itest-secret-fixed-0123456789';
    process.env.PD_USERNAME = 'itest-user';
    process.env.PD_PASSWORD = 'itest-password';
    process.env.PD_ACCESS_TEAM_DOMAIN = TEAM;
    process.env.PD_ACCESS_AUD = AUD;
    process.env.PD_ACCESS_CERTS_URL = 'http://127.0.0.1:' + jwksPort + '/cdn-cgi/access/certs';
    const app = require('../server.js');
    server = app.server;
    // Do NOT prime: the server starts keyless, exactly the boot-time outage.
    server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
  });
}));

test.after(() => new Promise((resolve) => server.close(() => jwksServer.close(resolve))));

function assertion() {
  const sec = Math.floor(Date.now() / 1000);
  const h = b64url(JSON.stringify({ alg: 'RS256', kid: keypair.kid, typ: 'JWT' }));
  const p = b64url(JSON.stringify({ iss: ISSUER, aud: AUD, exp: sec + 3600, iat: sec - 5, email: 'op@example.com' }));
  return h + '.' + p + '.' + b64url(crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p, 'ascii'), keypair.privateKey));
}

function request(opts) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, agent: false, ...opts }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject); r.end();
  });
}

test('a keyless origin answers enforced requests with 503 and Retry-After, not 403', async () => {
  const realErr = console.error; console.error = () => {}; // silence the loud no-keys logging
  let r;
  try { r = await request({ path: '/', method: 'GET', headers: { 'Cf-Access-Jwt-Assertion': assertion() } }); }
  finally { console.error = realErr; }
  assert.strictEqual(r.status, 503, 'a JWKS outage is OUR failure: try again, not forbidden');
  assert.strictEqual(r.headers['retry-after'], '30');
});

test('/healthz still answers 200 even while the origin is keyless', async () => {
  const r = await request({ path: '/healthz', method: 'GET' });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.body, 'ok');
});
