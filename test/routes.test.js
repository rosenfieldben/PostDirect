'use strict';
// Route-level integration tests against a REAL listening server. Env must be
// set before requiring server.js because credentials and the secret are read
// at module load. NODE_ENV=production is deliberately NOT set: the fail-fast
// guard is gated on require.main so it would not fire anyway, but keeping the
// test env unambiguous avoids surprises if that gating ever changes.
process.env.PD_SECRET = 'itest-secret-fixed-value';
process.env.PD_USERNAME = 'itest-user';
process.env.PD_PASSWORD = 'itest-pass';
// Trust X-Forwarded-For so the lockout tests can present distinct client IPs,
// isolating the per-username bucket from the per-IP one (all real connections
// here share 127.0.0.1). Read once at module load, hence set before require.
process.env.PD_TRUST_PROXY = '1';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { server } = require('../server.js');

let port;

test.before(() => new Promise((resolve) => {
  // Port 0 = OS-assigned ephemeral port, so parallel test runs never collide.
  server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
}));

test.after(() => new Promise((resolve) => server.close(resolve)));

// Minimal HTTP helper. Redirects are NOT followed: several assertions below
// are about the redirect responses themselves (Location, Set-Cookie).
// agent:false disables keep-alive so a socket the server destroyed (the 413
// path) is never reused by a later request.
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

function loginBody(user, pass) {
  return new URLSearchParams({ username: user, password: pass }).toString();
}

const FORM = { 'Content-Type': 'application/x-www-form-urlencoded' };

test('GET /login returns 200 with the login page and all four security headers', async () => {
  const r = await request({ path: '/login', method: 'GET' });
  assert.strictEqual(r.status, 200);
  assert.ok(r.body.includes('PostDirect'), 'login page HTML is served');
  assert.strictEqual(r.headers['x-content-type-options'], 'nosniff');
  assert.strictEqual(r.headers['x-frame-options'], 'DENY');
  assert.strictEqual(r.headers['referrer-policy'], 'no-referrer');
  assert.ok(r.headers['content-security-policy'], 'CSP header present');
});

test('full login round trip: valid POST sets a session cookie that unlocks /', async () => {
  const r = await request({ path: '/login', method: 'POST', headers: FORM }, loginBody('itest-user', 'itest-pass'));
  assert.strictEqual(r.status, 302);
  assert.strictEqual(r.headers.location, '/');
  const setCookie = String(r.headers['set-cookie']);
  assert.ok(setCookie.includes('pd_session='), 'session cookie is set');
  assert.ok(setCookie.includes('HttpOnly'), 'cookie is HttpOnly');
  assert.ok(setCookie.includes('SameSite=Strict'), 'cookie is SameSite=Strict');

  const cookie = setCookie.split(';')[0];
  const home = await request({ path: '/', method: 'GET', headers: { Cookie: cookie } });
  assert.strictEqual(home.status, 200, 'session cookie grants access to /');

  const anon = await request({ path: '/', method: 'GET' });
  assert.strictEqual(anon.status, 302);
  assert.strictEqual(anon.headers.location, '/login');
});

test('POST /login with wrong credentials returns 401', async () => {
  const r = await request({ path: '/login', method: 'POST', headers: FORM }, loginBody('itest-user', 'wrong-pass'));
  assert.strictEqual(r.status, 401);
  assert.strictEqual(r.headers['set-cookie'], undefined, 'no session cookie on failure');
});

test('proxy auth gate: unauthenticated /api/lob/* redirects to /login (never reaches Lob)', async () => {
  const r = await request({ path: '/api/lob/v1/letters', method: 'GET' });
  assert.strictEqual(r.status, 302);
  assert.strictEqual(r.headers.location, '/login');
});

test('oversized login body (> 16 KB) returns 413', async () => {
  const huge = 'username=' + 'a'.repeat(17 * 1024);
  const r = await request({ path: '/login', method: 'POST', headers: FORM }, huge);
  assert.strictEqual(r.status, 413);
});

test('lockout regression: correct credentials always log in, even with the username bucket full', async () => {
  // Start from a clean slate: earlier tests recorded failures for this
  // username, and a successful login clears both buckets.
  const clean = await request({ path: '/login', method: 'POST', headers: FORM }, loginBody('itest-user', 'itest-pass'));
  assert.strictEqual(clean.status, 302);

  // Simulate a spray against the known username from 5 distinct forged IPs:
  // this fills ONLY the username bucket. The first 4 wrong attempts get 401,
  // the 5th trips the cap and gets 429.
  for (let i = 1; i <= 5; i++) {
    const r = await request(
      { path: '/login', method: 'POST', headers: { ...FORM, 'X-Forwarded-For': '10.9.9.' + i } },
      loginBody('itest-user', 'wrong-pass-' + i)
    );
    assert.strictEqual(r.status, i < 5 ? 401 : 429, 'attempt ' + i);
  }

  // The single most important assertion in this suite: the real owner with
  // the correct password is NOT locked out by forged failures.
  const ok = await request(
    { path: '/login', method: 'POST', headers: { ...FORM, 'X-Forwarded-For': '10.9.10.1' } },
    loginBody('itest-user', 'itest-pass')
  );
  assert.strictEqual(ok.status, 302);
  assert.ok(String(ok.headers['set-cookie']).includes('pd_session='), 'session cookie issued');

  // Success cleared both buckets: a fresh wrong attempt is 401, not 429.
  const wrong = await request(
    { path: '/login', method: 'POST', headers: { ...FORM, 'X-Forwarded-For': '10.9.10.1' } },
    loginBody('itest-user', 'wrong-again')
  );
  assert.strictEqual(wrong.status, 401, 'buckets were cleared by the successful login');
});

test('traversal guard: nothing outside public/ is served', async () => {
  // Authenticate first so the request reaches serveStatic instead of bouncing
  // off the auth gate; the guard under test is the path check, not the login.
  const login = await request({ path: '/login', method: 'POST', headers: FORM }, loginBody('itest-user', 'itest-pass'));
  const cookie = String(login.headers['set-cookie']).split(';')[0];
  // Raw and percent-encoded dot-dot forms; server.js source contains the
  // string PD_PASSWORD, so its absence proves the file did not leak.
  for (const p of ['/../server.js', '/%2e%2e/server.js', '/..%2fserver.js', '/%2e%2e%2fserver.js']) {
    const r = await request({ path: p, method: 'GET', headers: { Cookie: cookie } });
    assert.ok(r.status === 403 || r.status === 404,
      p + ' must not be served (got ' + r.status + ')');
    assert.ok(!r.body.includes('PD_PASSWORD'), p + ' must not leak server.js source');
  }
});
