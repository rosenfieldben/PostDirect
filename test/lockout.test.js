'use strict';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const { bucketKey, recordAttempt, attemptBlocked } = require('../server.js');

test('bucketKey trims, truncates long input, and is stable for the same input', () => {
  assert.strictEqual(bucketKey('  alice  ', 256), 'alice');
  const huge = 'x'.repeat(16 * 1024);
  const k = bucketKey(huge, 256);
  assert.strictEqual(k.length, 256);
  assert.strictEqual(k, bucketKey(huge, 256), 'same input always yields the same key');
  assert.strictEqual(bucketKey(null, 256), '');
  assert.strictEqual(bucketKey(undefined, 256), '');
});

test('two inputs that share a 256-char prefix collapse to one bucket key', () => {
  // This is the memory bound working as intended: an attacker varying only
  // the tail of a huge username cannot mint unlimited distinct keys.
  const a = 'y'.repeat(300) + 'tail-one';
  const b = 'y'.repeat(300) + 'tail-two';
  assert.strictEqual(bucketKey(a, 256), bucketKey(b, 256));
});

test('recordAttempt refuses NEW keys at the cap but still increments existing ones', () => {
  // Seed the map directly at the 10,000-entry cap (looping recordAttempt with
  // distinct keys would be needlessly slow).
  const m = new Map();
  const now = Date.now();
  for (let i = 0; i < 10000; i++) m.set('seed' + i, { count: 1, first: now });

  recordAttempt(m, 'brand-new-key');
  assert.strictEqual(m.has('brand-new-key'), false, 'new key rejected at the cap');
  assert.strictEqual(m.size, 10000, 'map does not grow past the cap');

  recordAttempt(m, 'seed0');
  assert.strictEqual(m.get('seed0').count, 2, 'existing key still increments at the cap');
  for (let i = 0; i < 4; i++) recordAttempt(m, 'seed0');
  assert.strictEqual(attemptBlocked(m, 'seed0'), true, 'existing key still reaches blocked state');
});

test('below the cap, recordAttempt inserts new keys normally', () => {
  const m = new Map();
  recordAttempt(m, 'fresh');
  assert.strictEqual(m.get('fresh').count, 1);
});
