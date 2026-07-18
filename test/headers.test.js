'use strict';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const { setSecurityHeaders, escapeHtml } = require('../server.js');

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
  // few inline style="" attributes.
  assert.match(csp, /(^|; )style-src 'self' 'unsafe-inline' https:\/\/fonts\.googleapis\.com(;|$)/);
  assert.match(csp, /(^|; )font-src https:\/\/fonts\.gstatic\.com(;|$)/);
  assert.match(csp, /(^|; )img-src 'self' data:(;|$)/);
  assert.match(csp, /(^|; )connect-src 'self'(;|$)/);
  assert.match(csp, /(^|; )frame-ancestors 'none'(;|$)/);
  // No remote script/connect origins leaked in.
  assert.ok(!/script-src[^;]*https?:\/\//.test(csp), 'no remote script origins');
});

test('escapeHtml neutralizes markup and quotes for the login page error sink', () => {
  assert.strictEqual(escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
  assert.strictEqual(escapeHtml('a"b\'c&d'), 'a&quot;b&#39;c&amp;d');
  assert.strictEqual(escapeHtml(''), '');
  assert.strictEqual(escapeHtml(null), '');
  assert.strictEqual(escapeHtml(undefined), '');
});
