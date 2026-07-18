'use strict';
// Durable idempotency (item 3). The old in-memory per-recipient-id Map and its
// getOrCreateIdempotencyKey helper were REMOVED: they were discarded on
// reload/crash, after which resubmitting the same letter created duplicate
// physical mail. This suite now tests the shipped localStorage-backed,
// fingerprint-keyed persistence and the content canonicalization, extracted
// from public/index.html (same brace-matched technique as multipart.test.js).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
function fnSrc(name) {
  // Capture an optional `async ` prefix so async function bodies keep their
  // keyword (without it, the extracted source has a bare `await` and throws).
  const m = new RegExp('(?:async\\s+)?function\\s+' + name + '\\s*\\(').exec(SRC);
  if (!m) throw new Error('function not found in index.html: ' + name);
  let i = SRC.indexOf('{', m.index), depth = 0;
  for (; i < SRC.length; i++) { const c = SRC[i]; if (c === '{') depth++; else if (c === '}' && --depth === 0) { i++; break; } }
  return SRC.slice(m.index, i);
}
// The persistence + fingerprint functions reference the module-level constants
// IDEMPOTENCY_STORE_KEY / IDEMPOTENCY_TTL_MS and the global `crypto` (Web
// Crypto). Provide both to the sandbox: the constants as literals, and Node's
// webcrypto as `crypto` (so subtle.digest works on Node 18+).
const CONSTS = "const IDEMPOTENCY_STORE_KEY = 'pd_idempotency_v1';\nconst IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;\n";
const NAMES = ['canonicalizeSendInput', 'sha256HexOf', 'computeFingerprint', 'pruneIdempotencyStore',
  'loadIdempotencyStore', 'saveIdempotencyStore', 'getOrCreatePersistedKey', 'recordSentLetter'];
const api = (new Function('crypto',
  CONSTS + NAMES.map(fnSrc).join('\n') + '\nreturn { ' + NAMES.join(', ') + ' };'
))(crypto.webcrypto);
const {
  canonicalizeSendInput, computeFingerprint, pruneIdempotencyStore,
  getOrCreatePersistedKey, recordSentLetter, loadIdempotencyStore,
} = api;

// A minimal localStorage stand-in.
function fakeStorage(initial) {
  const map = new Map(Object.entries(initial || {}));
  return {
    getItem: (k) => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => { map.set(k, String(v)); },
    _dump: () => JSON.parse(map.get('pd_idempotency_v1') || '{}'),
  };
}

const TTL = 24 * 60 * 60 * 1000;

test('canonicalizeSendInput is key-order and whitespace stable', () => {
  const r1 = { name: '  Jane  ', line1: '1 Main St', city: 'NYC', state: 'NY', zip: '10001' };
  const r2 = { zip: '10001', state: 'NY', city: 'NYC', line1: '1 Main St', name: 'Jane' };
  const optsA = [['mail_type', 'usps_first_class'], ['color', 'false']];
  const optsB = { color: 'false', mail_type: 'usps_first_class' };
  assert.strictEqual(
    canonicalizeSendInput(r1, optsA, 'abc'),
    canonicalizeSendInput(r2, optsB, 'abc'),
    'reordered keys and extra whitespace must not change the canonical string'
  );
  // A real change (different file hash, or a changed field) changes the string.
  assert.notStrictEqual(canonicalizeSendInput(r1, optsA, 'abc'), canonicalizeSendInput(r1, optsA, 'xyz'));
  assert.notStrictEqual(canonicalizeSendInput(r1, optsA, 'abc'),
    canonicalizeSendInput(Object.assign({}, r1, { zip: '10002' }), optsA, 'abc'));
});

test('computeFingerprint is a stable 64-hex digest of the canonical input', async () => {
  const r = { name: 'Jane', line1: '1 Main St', city: 'NYC', state: 'NY', zip: '10001' };
  const opts = [['mail_type', 'usps_first_class']];
  const fp1 = await computeFingerprint(r, opts, 'filehash');
  const fp2 = await computeFingerprint(r, opts, 'filehash');
  assert.match(fp1, /^[0-9a-f]{64}$/);
  assert.strictEqual(fp1, fp2, 'same input, same fingerprint');
  // Matches an independent SHA-256 of the canonical string.
  const canonical = canonicalizeSendInput(r, opts, 'filehash');
  const expected = crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex');
  assert.strictEqual(fp1, expected);
});

test('getOrCreatePersistedKey mints once and reuses within the 24h window (survives reload)', () => {
  const storage = fakeStorage();
  let n = 0;
  const uuid = () => 'uuid-' + (++n);
  const t0 = 1_000_000_000_000;
  const first = getOrCreatePersistedKey(storage, 'fp1', t0, uuid);
  assert.strictEqual(first.idempotencyKey, 'uuid-1');
  // A "reload" is just a fresh storage object over the SAME persisted bytes.
  const reloaded = fakeStorage({ pd_idempotency_v1: storage.getItem('pd_idempotency_v1') });
  const again = getOrCreatePersistedKey(reloaded, 'fp1', t0 + 60_000, uuid);
  assert.strictEqual(again.idempotencyKey, 'uuid-1', 'same key reused across a reload within the window');
  assert.strictEqual(n, 1, 'uuid generator not called again');
});

test('a resubmit past the 24h window mints a fresh key', () => {
  const storage = fakeStorage();
  let n = 0;
  const uuid = () => 'uuid-' + (++n);
  const t0 = 1_000_000_000_000;
  getOrCreatePersistedKey(storage, 'fp1', t0, uuid);
  const later = getOrCreatePersistedKey(storage, 'fp1', t0 + TTL + 1, uuid);
  assert.strictEqual(later.idempotencyKey, 'uuid-2', 'expired entry is pruned, a new key minted');
});

test('pruneIdempotencyStore drops only entries past the window', () => {
  const now = 2_000_000_000_000;
  const store = {
    fresh: { idempotencyKey: 'a', createdAt: now - 1000 },
    stale: { idempotencyKey: 'b', createdAt: now - TTL - 1 },
    edge: { idempotencyKey: 'c', createdAt: now - TTL + 1 },
    junk: { idempotencyKey: 'd' }, // no createdAt -> dropped
  };
  const pruned = pruneIdempotencyStore(store, now);
  assert.deepStrictEqual(Object.keys(pruned).sort(), ['edge', 'fresh']);
});

test('recordSentLetter annotates the persisted record with the letter id', () => {
  const storage = fakeStorage();
  const t0 = 1_000_000_000_000;
  getOrCreatePersistedKey(storage, 'fp1', t0, () => 'uuid-1');
  recordSentLetter(storage, 'fp1', 'ltr_abc', t0 + 1000);
  assert.strictEqual(storage._dump().fp1.letterId, 'ltr_abc');
  assert.strictEqual(storage._dump().fp1.idempotencyKey, 'uuid-1', 'the key is preserved');
});

test('corrupt localStorage JSON is treated as empty, not a crash', () => {
  const storage = fakeStorage({ pd_idempotency_v1: '{not valid json' });
  const loaded = loadIdempotencyStore(storage, Date.now());
  assert.deepStrictEqual(loaded, {});
});
