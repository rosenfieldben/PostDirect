'use strict';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const { attemptBlocked, recordAttempt, clearAttempts, clientIp, parseCookies } = require('../server.js');

test('a bucket blocks after 5 failures and clears on success', () => {
  const m = new Map();
  const seen = [];
  for (let i = 0; i < 6; i++) { seen.push(attemptBlocked(m, 'k')); recordAttempt(m, 'k'); }
  assert.deepStrictEqual(seen, [false, false, false, false, false, true]);
  clearAttempts(m, 'k');
  assert.strictEqual(attemptBlocked(m, 'k'), false);
});

test('buckets are independent per key (IP vs username, or two users)', () => {
  const m = new Map();
  for (let i = 0; i < 5; i++) recordAttempt(m, 'alice');
  assert.strictEqual(attemptBlocked(m, 'alice'), true);
  assert.strictEqual(attemptBlocked(m, 'bob'), false);
});

test('the rolling window expires and unblocks (deterministic via Date.now stub)', () => {
  const realNow = Date.now;
  let t = 1_000_000;
  Date.now = () => t;
  try {
    const m = new Map();
    for (let i = 0; i < 5; i++) recordAttempt(m, 'k');
    assert.strictEqual(attemptBlocked(m, 'k'), true);
    t += 15 * 60 * 1000 + 1; // advance just past the 15-minute window
    assert.strictEqual(attemptBlocked(m, 'k'), false, 'expired window unblocks');
  } finally {
    Date.now = realNow;
  }
});

test('clientIp ignores X-Forwarded-For by default (no PD_TRUST_PROXY)', () => {
  assert.strictEqual(clientIp({ headers: { 'x-forwarded-for': '1.2.3.4' }, socket: { remoteAddress: '10.0.0.9' } }), '10.0.0.9');
  assert.strictEqual(clientIp({ headers: {}, socket: {} }), 'unknown');
});

test('clientIp ignores CF-Connecting-IP unless Access enforcement is passed', () => {
  const req = { headers: { 'cf-connecting-ip': '9.9.9.9' }, socket: { remoteAddress: '10.0.0.9' } };
  assert.strictEqual(clientIp(req), '10.0.0.9', 'unenforced: the CF header is not trusted, socket wins');
  assert.strictEqual(clientIp(req, true), '9.9.9.9', 'enforced: the CF header is the authoritative identity');
});

test('parseCookies preserves values containing "="', () => {
  const c = parseCookies('a=b=c; pd_session=1700000000000.deadbeef');
  assert.strictEqual(c.a, 'b=c');
  assert.strictEqual(c.pd_session, '1700000000000.deadbeef');
  assert.deepStrictEqual(parseCookies(''), {});
  assert.deepStrictEqual(parseCookies(undefined), {});
});
