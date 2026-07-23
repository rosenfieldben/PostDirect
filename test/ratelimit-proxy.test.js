'use strict';
// PD_TRUST_PROXY is read once at module load, so set it BEFORE requiring server.
// node --test runs each test file in its own process, so this does not affect
// the default-off behavior asserted in ratelimit.test.js.
process.env.PD_TRUST_PROXY = '1';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const { clientIp } = require('../server.js');

test('clientIp trusts the leftmost X-Forwarded-For entry when PD_TRUST_PROXY=1', () => {
  assert.strictEqual(
    clientIp({ headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }, socket: { remoteAddress: '10.0.0.9' } }),
    '1.2.3.4'
  );
});

test('clientIp falls back to the socket address when XFF is absent or empty', () => {
  assert.strictEqual(clientIp({ headers: {}, socket: { remoteAddress: '10.0.0.9' } }), '10.0.0.9');
  assert.strictEqual(clientIp({ headers: { 'x-forwarded-for': '   ' }, socket: { remoteAddress: '10.0.0.9' } }), '10.0.0.9');
});

test('under Access enforcement, CF-Connecting-IP wins over a decoy leftmost X-Forwarded-For', () => {
  // Behind Cloudflare plus Railway, the edge sets CF-Connecting-IP
  // authoritatively while leftmost XFF is client-influenced. When enforcement is
  // ON, the former is the rate-limit identity even though PD_TRUST_PROXY is set.
  const req = { headers: { 'cf-connecting-ip': '9.9.9.9', 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }, socket: { remoteAddress: '10.0.0.9' } };
  assert.strictEqual(clientIp(req, true), '9.9.9.9', 'enforced: CF-Connecting-IP is the identity');
  // Unenforced (the flag absent/false): CF-Connecting-IP is ignored and the
  // existing PD_TRUST_PROXY behavior (leftmost XFF) is untouched.
  assert.strictEqual(clientIp(req, false), '1.2.3.4', 'unenforced: existing XFF behavior, CF header ignored');
  assert.strictEqual(clientIp(req), '1.2.3.4', 'the flag defaults to unenforced');
  // The CF-Connecting-IP is canonicalized through the same RFC 5952 path.
  assert.strictEqual(clientIp({ headers: { 'cf-connecting-ip': '2001:DB8::1' }, socket: {} }, true), '2001:db8::/64');
});
