'use strict';
// Durable idempotency (item 3). The old in-memory per-recipient-id Map and its
// getOrCreateIdempotencyKey helper were REMOVED: they were discarded on
// reload/crash, after which resubmitting the same letter created duplicate
// physical mail. This suite now tests the shipped localStorage-backed,
// fingerprint-keyed persistence and the content canonicalization, imported
// directly from the shipped ES module js/idempotency.mjs.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto'); // for an INDEPENDENT expected hash below

// Import the shipped idempotency ES module (js/idempotency.mjs). Its fingerprint
// helpers use the global Web Crypto (crypto.subtle), which Node exposes as
// globalThis.crypto, and every persistence helper takes localStorage as an
// explicit parameter (fakeStorage below), so nothing needs to be injected. The
// IDEMPOTENCY_STORE_KEY / IDEMPOTENCY_TTL_MS constants live inside the module.
const {
  canonicalizeSendInput, computeFingerprint, pruneIdempotencyStore,
  getOrCreatePersistedKey, recordSentLetter, loadIdempotencyStore,
} = require('../public/js/idempotency.mjs');

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

test('the fingerprint ignores the ephemeral recipient id and any unknown key', async () => {
  // The DOM id that readRecipientFromDOM attaches is incremented by "Send another
  // letter", so an identical letter must fingerprint the same with id 1, id 2, or
  // no id at all, or the in-session Send Another flow silently duplicates mail.
  const addr = { name: 'Jane', company: 'Acme', line1: '1 Main St', line2: 'Ste 2', city: 'NYC', state: 'NY', zip: '10001' };
  const opts = [['mail_type', 'usps_first_class']];
  const base = await computeFingerprint(addr, opts, 'h');
  assert.strictEqual(await computeFingerprint(Object.assign({ id: 1 }, addr), opts, 'h'), base);
  assert.strictEqual(await computeFingerprint(Object.assign({ id: 2 }, addr), opts, 'h'), base);
  assert.strictEqual(
    await computeFingerprint(Object.assign({ id: 1 }, addr), opts, 'h'),
    await computeFingerprint(Object.assign({ id: 2 }, addr), opts, 'h'),
    'id 1 vs id 2 must not change the fingerprint'
  );
  // Any other unknown key that rides along on the recipient is likewise excluded.
  assert.strictEqual(await computeFingerprint(Object.assign({ somethingNew: 'x' }, addr), opts, 'h'), base);
});

test('the fingerprint changes when any allowlisted recipient field changes', async () => {
  const addr = { name: 'Jane', company: 'Acme', line1: '1 Main St', line2: 'Ste 2', city: 'NYC', state: 'NY', zip: '10001' };
  const opts = [['mail_type', 'usps_first_class']];
  const base = await computeFingerprint(addr, opts, 'h');
  for (const field of ['name', 'company', 'line1', 'line2', 'city', 'state', 'zip']) {
    const changed = Object.assign({}, addr, { [field]: addr[field] + '-X' });
    assert.notStrictEqual(await computeFingerprint(changed, opts, 'h'), base, field + ' must affect the fingerprint');
  }
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
