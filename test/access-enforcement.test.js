'use strict';
// Item 2: Cloudflare Access origin enforcement in the REAL server, against a fake
// JWKS stub. Boots the app in-process (the routes/headers pattern) with
// enforcement configured and the JWKS client primed from the stub, then drives
// the perimeter. The non-negotiable case is the BYPASS GUARD: a valid PostDirect
// session with NO assertion is still refused, proving the perimeter cannot be
// walked around by anyone who reaches (or forges their way to) the inner login.
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
const AUD = 'aud-p3c-test';

let jwksServer, keypair, server, port, DATA_DIR;

test.before(() => new Promise((resolve) => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' }); jwk.kid = 'fake-kid-1'; jwk.alg = 'RS256'; jwk.use = 'sig';
  keypair = { privateKey, kid: 'fake-kid-1' };
  jwksServer = http.createServer((req, res) => {
    if (req.url === '/cdn-cgi/access/certs') { res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ keys: [jwk] })); return; }
    res.writeHead(404); res.end();
  });
  jwksServer.listen(0, '127.0.0.1', () => {
    const jwksPort = jwksServer.address().port;
    DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-access-'));
    process.env.PD_DATA_DIR = DATA_DIR;
    process.env.PD_SECRET = 'access-itest-secret-fixed-0123456789';
    process.env.PD_USERNAME = 'itest-user';
    process.env.PD_PASSWORD = 'itest-password';
    process.env.PD_ACCESS_TEAM_DOMAIN = TEAM;
    process.env.PD_ACCESS_AUD = AUD;
    process.env.PD_ACCESS_CERTS_URL = 'http://127.0.0.1:' + jwksPort + '/cdn-cgi/access/certs';
    const app = require('../server.js');
    server = app.server;
    assert.strictEqual(app.accessEnforcer.enabled, true, 'enforcement is on for this suite');
    // Prime the JWKS cache from the stub (start() is entrypoint-only, so the
    // in-process test triggers the fetch itself).
    app.accessClient.forceRefresh(Date.now()).then(() => {
      server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
    });
  });
}));

test.after(() => new Promise((resolve) => server.close(() => jwksServer.close(resolve))));

function assertion(over) {
  const sec = Math.floor(Date.now() / 1000);
  const claims = Object.assign({ iss: ISSUER, aud: AUD, exp: sec + 3600, iat: sec - 5, email: 'op@example.com' }, over || {});
  const h = b64url(JSON.stringify({ alg: 'RS256', kid: keypair.kid, typ: 'JWT' }));
  const p = b64url(JSON.stringify(claims));
  return h + '.' + p + '.' + b64url(crypto.sign('RSA-SHA256', Buffer.from(h + '.' + p, 'ascii'), keypair.privateKey));
}
const A = () => ({ 'Cf-Access-Jwt-Assertion': assertion() });

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, agent: false, ...opts }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject); if (body) r.write(body); r.end();
  });
}

async function login() {
  const r = await request({ path: '/login', method: 'POST', headers: { ...A(), 'Content-Type': 'application/x-www-form-urlencoded' } },
    'username=itest-user&password=itest-password');
  return String(r.headers['set-cookie']).split(';')[0];
}

test('a valid assertion plus a valid session reaches the app', async () => {
  const cookie = await login();
  const r = await request({ path: '/', method: 'GET', headers: { ...A(), Cookie: cookie } });
  assert.strictEqual(r.status, 200);
});

test('a valid assertion with NO session still gets the normal 302 to /login (the inner layer is intact)', async () => {
  const r = await request({ path: '/', method: 'GET', headers: A() });
  assert.strictEqual(r.status, 302);
  assert.strictEqual(r.headers.location, '/login');
});

test('no assertion is 403 on /, /login, a static asset, and an /api route', async () => {
  for (const p of ['/', '/login', '/css/app.css', '/api/config']) {
    const r = await request({ path: p, method: 'GET' });
    assert.strictEqual(r.status, 403, p + ' must be 403 without an assertion');
    assert.match(r.body, /Forbidden/);
  }
});

test('BYPASS GUARD: a valid session cookie but NO assertion is refused 403 before the session is consulted', async () => {
  const cookie = await login();                                             // a genuine, valid session
  const r = await request({ path: '/', method: 'GET', headers: { Cookie: cookie } }); // ...but no assertion
  assert.strictEqual(r.status, 403, 'the perimeter refuses even a valid session when the assertion is absent');
  assert.match(r.body, /Forbidden/);
});

test('a bad assertion is 403 and the failed check is not leaked to the client', async () => {
  const r = await request({ path: '/', method: 'GET', headers: { 'Cf-Access-Jwt-Assertion': assertion({ aud: 'wrong-aud' }) } });
  assert.strictEqual(r.status, 403);
  assert.doesNotMatch(r.body, /aud|iss|signature|kid|expired/i, 'the generic body reveals no detail about which check failed');
});

test('the CF_Authorization cookie is NOT an accepted carrier (header only)', async () => {
  // Presenting the JWT via the cookie Cloudflare also sets must not satisfy the
  // perimeter: one carrier, no cookie-shaped surface.
  const r = await request({ path: '/', method: 'GET', headers: { Cookie: 'CF_Authorization=' + assertion() } });
  assert.strictEqual(r.status, 403, 'a valid JWT in the cookie is ignored; only the header carries it');
});

test('/healthz is 200 with NO assertion under enforcement, and inert', async () => {
  const r = await request({ path: '/healthz', method: 'GET' });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.body, 'ok');
  assert.strictEqual(r.headers['cache-control'], 'no-store');
});
