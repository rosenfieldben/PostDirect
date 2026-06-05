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
