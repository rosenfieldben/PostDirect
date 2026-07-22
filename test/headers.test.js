'use strict';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';
// Credentials are read at server.js load, so set them before the require below;
// the live Cache-Control test logs in to reach the authed routes.
process.env.PD_USERNAME = 'hdr-user';
process.env.PD_PASSWORD = 'hdr-password-1';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { server, setSecurityHeaders, escapeHtml } = require('../server.js');

function fakeRes() {
  const headers = {};
  return { setHeader: (k, v) => { headers[k.toLowerCase()] = v; }, headers };
}

test('setSecurityHeaders sets the expected hardening headers', () => {
  const res = fakeRes();
  setSecurityHeaders(res);
  assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
  assert.strictEqual(res.headers['x-frame-options'], 'DENY');
  assert.strictEqual(res.headers['referrer-policy'], 'no-referrer');
  assert.strictEqual(res.headers['cache-control'], 'no-store', 'no-store is the default');
});

test('Cache-Control: no-store on pages/API, private caching only for non-HTML static assets', async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const get = (path, headers) => new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, agent: false, path, method: 'GET', headers }, (res) => {
      res.resume(); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers }));
    });
    r.on('error', reject); r.end();
  });
  try {
    // Pre-auth login page (HTML): no-store.
    assert.strictEqual((await get('/login')).headers['cache-control'], 'no-store');
    // Authenticate to reach the gated routes.
    const cookie = await new Promise((resolve, reject) => {
      const body = new URLSearchParams({ username: 'hdr-user', password: 'hdr-password-1' }).toString();
      const r = http.request({ host: '127.0.0.1', port, agent: false, path: '/login', method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
        (res) => { res.resume(); res.on('end', () => resolve(String(res.headers['set-cookie']).split(';')[0])); });
      r.on('error', reject); r.write(body); r.end();
    });
    const authed = { Cookie: cookie };
    // App shell (authed HTML) and a representative /api/ JSON response: no-store.
    const home = await get('/', authed);
    assert.strictEqual(home.status, 200);
    assert.strictEqual(home.headers['cache-control'], 'no-store');
    assert.strictEqual((await get('/api/config', authed)).headers['cache-control'], 'no-store');
    // Code coupled to the HTML shell (css, js, mjs) stays no-store, so a deploy
    // never leaves a browser on fresh HTML with a stale cached module/stylesheet.
    const css = await get('/css/app.css', authed);
    assert.strictEqual(css.status, 200);
    assert.strictEqual(css.headers['cache-control'], 'no-store', 'css is code: no-store');
    assert.strictEqual((await get('/js/app.mjs', authed)).headers['cache-control'], 'no-store', 'js module is code: no-store');
    // Standalone content assets (fonts) keep the private cache: not markup-coupled.
    assert.strictEqual((await get('/fonts/source-serif-4-roman-latin.woff2', authed)).headers['cache-control'], 'private, max-age=3600');
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test('CSP allows exactly what the app needs and nothing looser', () => {
  const res = fakeRes();
  setSecurityHeaders(res);
  const csp = res.headers['content-security-policy'];
  assert.ok(csp, 'CSP header is set');
  assert.match(csp, /(^|; )default-src 'self'(;|$)/);
  // Item 4 hardening: script-src is 'self' with NO 'unsafe-inline'. All app JS
  // is external ES modules under /js and neither page carries an inline <script>
  // or on*= handler, so inline script injection can no longer execute.
  assert.match(csp, /(^|; )script-src 'self'(;|$)/);
  assert.ok(!/script-src[^;]*'unsafe-inline'/.test(csp), "script-src must not allow 'unsafe-inline'");
  // style-src still allows 'unsafe-inline': the login page is served pre-auth and
  // its stylesheet cannot be an authenticated /css asset, and the app page uses a
  // few inline style="" attributes. The font is self-hosted now, so style-src and
  // font-src carry no remote origins.
  assert.match(csp, /(^|; )style-src 'self' 'unsafe-inline'(;|$)/);
  assert.match(csp, /(^|; )font-src 'self'(;|$)/);
  assert.match(csp, /(^|; )img-src 'self' data:(;|$)/);
  assert.match(csp, /(^|; )connect-src 'self'(;|$)/);
  assert.match(csp, /(^|; )frame-ancestors 'none'(;|$)/);
  // The point of self-hosting the font: the policy names no third-party origin
  // anywhere. Every source is 'self' (plus 'unsafe-inline'/data:/'none' keywords).
  assert.ok(!/https?:\/\//.test(csp), 'no remote origins anywhere in the CSP');
});

test('escapeHtml neutralizes markup and quotes for the login page error sink', () => {
  assert.strictEqual(escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
  assert.strictEqual(escapeHtml('a"b\'c&d'), 'a&quot;b&#39;c&amp;d');
  assert.strictEqual(escapeHtml(''), '');
  assert.strictEqual(escapeHtml(null), '');
  assert.strictEqual(escapeHtml(undefined), '');
});
