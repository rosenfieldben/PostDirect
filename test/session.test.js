'use strict';
// Stable secret so signatures are deterministic; must be set BEFORE requiring server.
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const { createSession, validateSession, signValue, safeEqual } = require('../server.js');

test('createSession round-trips through validateSession', () => {
  const tok = createSession();
  assert.match(tok, /^[0-9]+\.[0-9a-f]{64}$/, 'token shape is <issuedAt>.<sha256-hexsig>');
  assert.strictEqual(validateSession(tok), true);
});

test('validateSession rejects a tampered signature', () => {
  const tok = createSession();
  const dot = tok.indexOf('.');
  const iat = tok.slice(0, dot);
  const sig = tok.slice(dot + 1);
  const last = sig.slice(-1);
  const flipped = sig.slice(0, -1) + (last === '0' ? '1' : '0');
  assert.strictEqual(validateSession(iat + '.' + flipped), false);
});

test('validateSession rejects malformed tokens', () => {
  const bad = [
    '', null, undefined,
    'no-dot',
    '.',                         // empty issuedAt + empty sig
    'abc.def',                   // non-numeric issuedAt, non-hex sig
    '123.',                      // empty signature
    '.' + signValue('123'),      // empty issuedAt
    '12x.' + signValue('12x'),   // issuedAt not all digits
    '123.zzzz',                  // signature not hex
    '123.' + signValue('123') + 'ab', // wrong-length signature
  ];
  for (const t of bad) {
    assert.strictEqual(validateSession(t), false, 'should reject: ' + JSON.stringify(t));
  }
});

test('validateSession rejects an expired issuedAt (with a valid signature)', () => {
  const old = String(Date.now() - 8 * 24 * 60 * 60 * 1000); // 8 days ago > 7-day max
  const tok = old + '.' + signValue(old);
  assert.strictEqual(validateSession(tok), false);
});

test('validateSession accepts a recent issuedAt (with a valid signature)', () => {
  const recent = String(Date.now() - 1000);
  assert.strictEqual(validateSession(recent + '.' + signValue(recent)), true);
});

test('safeEqual: equal / unequal-same-length / different-length', () => {
  assert.strictEqual(safeEqual('hunter2', 'hunter2'), true);
  assert.strictEqual(safeEqual('hunter2', 'hunterX'), false); // same length, differ
  assert.strictEqual(safeEqual('short', 'a-much-longer-secret'), false); // different length
  assert.strictEqual(safeEqual('', ''), true);
  assert.strictEqual(safeEqual('admin', 'Admin'), false); // case-sensitive
});
