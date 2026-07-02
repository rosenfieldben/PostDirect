'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Extract the REAL getOrCreateIdempotencyKey() from public/index.html and
// evaluate it, so this suite tests the shipped code (same technique as
// multipart.test.js: brace-matched function extraction).
const SRC = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
function fnSrc(name) {
  const m = new RegExp('function\\s+' + name + '\\s*\\(').exec(SRC);
  if (!m) throw new Error('function not found in index.html: ' + name);
  let i = SRC.indexOf('{', m.index), depth = 0;
  for (; i < SRC.length; i++) { const c = SRC[i]; if (c === '{') depth++; else if (c === '}' && --depth === 0) { i++; break; } }
  return SRC.slice(m.index, i);
}
const { getOrCreateIdempotencyKey } =
  (new Function(fnSrc('getOrCreateIdempotencyKey') + '\nreturn { getOrCreateIdempotencyKey };'))();

test('mints a key on first use and stores it in the map', () => {
  const map = new Map();
  let calls = 0;
  const key = getOrCreateIdempotencyKey(map, 7, () => { calls++; return 'uuid-1'; });
  assert.strictEqual(key, 'uuid-1');
  assert.strictEqual(map.get(7), 'uuid-1');
  assert.strictEqual(calls, 1);
});

test('reuses the SAME key on a retry (the core duplicate-send guard)', () => {
  const map = new Map();
  let calls = 0;
  const first = getOrCreateIdempotencyKey(map, 7, () => 'uuid-' + (++calls));
  const retry = getOrCreateIdempotencyKey(map, 7, () => 'uuid-' + (++calls));
  assert.strictEqual(first, retry, 'a failed send retried must present the same key to Lob');
  assert.strictEqual(calls, 1, 'uuid generator not called again on retry');
});

test('distinct recipients get distinct keys', () => {
  const map = new Map();
  let calls = 0;
  const a = getOrCreateIdempotencyKey(map, 1, () => 'uuid-' + (++calls));
  const b = getOrCreateIdempotencyKey(map, 2, () => 'uuid-' + (++calls));
  assert.notStrictEqual(a, b);
  assert.strictEqual(map.size, 2);
});

test('after success-delete, the next send mints a fresh key (no replay)', () => {
  const map = new Map();
  let calls = 0;
  const first = getOrCreateIdempotencyKey(map, 7, () => 'uuid-' + (++calls));
  map.delete(7); // what sendLetters does on a confirmed success
  const next = getOrCreateIdempotencyKey(map, 7, () => 'uuid-' + (++calls));
  assert.notStrictEqual(first, next, 'an intentional re-send must be a new letter');
});
