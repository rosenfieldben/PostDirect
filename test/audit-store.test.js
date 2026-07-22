'use strict';
// Unit tests for the persistence layer (item 1). PD_DATA_DIR is pointed at a
// path that does NOT exist before requiring server.js, so we can assert that
// merely requiring the module creates no directories (ground rule: no
// filesystem side effects at module load). The store functions themselves take
// the directory explicitly and are tested against fresh fs.mkdtemp dirs.
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value-0123456789';
const NEVER_CREATED = path.join(os.tmpdir(), 'pd-should-not-exist-' + process.pid);
process.env.PD_DATA_DIR = NEVER_CREATED;

const test = require('node:test');
const assert = require('node:assert');
const store = require('../server.js');

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pd-audit-'));
}

test('requiring server.js creates no directories', () => {
  assert.strictEqual(fs.existsSync(NEVER_CREATED), false,
    'module load must not create the configured PD_DATA_DIR');
  assert.strictEqual(store.DATA_DIR, path.resolve(NEVER_CREATED), 'DATA_DIR resolved from env');
});

test('sha256Hex matches node crypto', () => {
  const buf = Buffer.from('hello world');
  const crypto = require('node:crypto');
  assert.strictEqual(store.sha256Hex(buf), crypto.createHash('sha256').update(buf).digest('hex'));
});

test('auditReadStats parses good lines around a corrupt MIDDLE line and counts the corruption', () => {
  const dir = tmpDir();
  store.ensureDataDir(dir);
  // A corrupt line in the middle, not just a truncated tail: valid, junk, valid.
  fs.writeFileSync(path.join(dir, 'audit.log'),
    JSON.stringify({ type: 'letter.create', letterId: 'ltr_a' }) + '\n' +
    '{ this is not valid json\n' +
    JSON.stringify({ type: 'letter.cancel', letterId: 'ltr_b' }) + '\n');
  const { lines, corruptCount } = store.auditReadStats(dir);
  assert.strictEqual(corruptCount, 1, 'the middle corrupt line is counted');
  assert.strictEqual(lines.length, 2, 'both valid lines still parse');
  assert.strictEqual(lines[0].letterId, 'ltr_a', 'the line before the corruption parsed');
  assert.strictEqual(lines[1].letterId, 'ltr_b', 'the line after the corruption parsed');

  const clean = tmpDir();
  store.ensureDataDir(clean);
  store.auditAppend(clean, { type: 'letter.create', letterId: 'ltr_c' });
  assert.strictEqual(store.auditReadStats(clean).corruptCount, 0, 'a clean log reports zero');
});

test('data-dir permissions are enforced to 0700/0600 even when the dir pre-exists 0755', () => {
  // The Docker image (and a bind mount or restored backup) can hand us a data
  // directory that already exists with a looser mode, where mkdir's mode is a
  // no-op. ensureDataDir must tighten it, and the writers must create their files
  // 0600. (CI is Linux; these mode bits are meaningful here.)
  const dir = tmpDir();
  fs.chmodSync(dir, 0o755);
  const r = store.ensureDataDir(dir);
  assert.strictEqual(r.ok, true, 'ensureDataDir reports the dir usable');
  store.auditAppend(dir, { type: 'test.perm' }, 1_000_000_000_000);
  const blobHex = store.blobStore(dir, Buffer.from('rendered pdf bytes'));
  const mode = (p) => fs.statSync(p).mode & 0o777;
  assert.strictEqual(mode(dir), 0o700, 'data dir tightened to 0700');
  assert.strictEqual(mode(path.join(dir, 'blobs')), 0o700, 'blobs dir 0700');
  assert.strictEqual(mode(path.join(dir, 'audit.log')), 0o600, 'audit.log created 0600');
  assert.strictEqual(mode(path.join(dir, 'blobs', blobHex)), 0o600, 'blob file created 0600');
});

test('normalizeAddressForHash is case/whitespace stable and ZIP-prefix stable', () => {
  const a = { line1: '185 Berry St', line2: 'Ste 6100', city: 'San Francisco', state: 'CA', zip: '94107' };
  const b = { line1: '185  BERRY   ST', line2: 'ste 6100', city: 'san francisco', state: 'ca', zip: '94107-1234' };
  assert.strictEqual(store.normalizeAddressForHash(a), store.normalizeAddressForHash(b),
    'case, extra whitespace, and ZIP+4 must not change the canonical form');
  assert.strictEqual(store.addressHash(a), store.addressHash(b));
  const c = { line1: '186 Berry St', line2: 'Ste 6100', city: 'San Francisco', state: 'CA', zip: '94107' };
  assert.notStrictEqual(store.addressHash(a), store.addressHash(c), 'a real difference changes the hash');
});

test('ensureDataDir creates a 0700 tree and probes writability', () => {
  const dir = path.join(tmpDir(), 'nested', 'data');
  const r = store.ensureDataDir(dir);
  assert.strictEqual(r.ok, true);
  assert.ok(fs.existsSync(dir), 'data dir created');
  assert.ok(fs.existsSync(path.join(dir, 'blobs')), 'blobs/ created');
  assert.strictEqual(fs.existsSync(path.join(dir, '.pd-write-test')), false, 'probe file removed');
});

test('ensureDataDir reports failure for an unusable path (parent is a file)', () => {
  const base = tmpDir();
  const asFile = path.join(base, 'a-file');
  fs.writeFileSync(asFile, 'x');
  const r = store.ensureDataDir(path.join(asFile, 'sub')); // parent is a regular file -> ENOTDIR
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /not usable/);
});

test('auditAppend writes one JSONL line per event with an injected ts, append-only', () => {
  const dir = tmpDir();
  const t0 = Date.parse('2026-07-18T12:00:00.000Z');
  store.auditAppend(dir, { type: 'letter.create', letterId: 'ltr_a' }, t0);
  store.auditAppend(dir, { type: 'letter.cancel', letterId: 'ltr_a' }, t0 + 1000);
  const raw = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8');
  const lines = raw.split('\n').filter(Boolean);
  assert.strictEqual(lines.length, 2);
  const first = JSON.parse(lines[0]);
  assert.strictEqual(first.ts, '2026-07-18T12:00:00.000Z');
  assert.strictEqual(first.type, 'letter.create');
  // ts is the first key so events are self-describing at a glance.
  assert.strictEqual(Object.keys(first)[0], 'ts');
});

test('blobStore is content-addressed and write-once; readBlob round-trips; blobPath validates', () => {
  const dir = tmpDir();
  const buf = Buffer.from('the exact bytes sent upstream');
  const hex = store.blobStore(dir, buf);
  assert.match(hex, /^[0-9a-f]{64}$/);
  assert.strictEqual(hex, store.sha256Hex(buf));
  // Identical content dedupes and does not throw on the second write.
  assert.strictEqual(store.blobStore(dir, buf), hex);
  assert.deepStrictEqual(store.readBlob(dir, hex), buf);
  // Path validation: a non-64-hex ref is rejected before any fs access.
  assert.strictEqual(store.blobPath(dir, '../etc/passwd'), null);
  assert.strictEqual(store.blobPath(dir, 'ZZZ'), null);
  assert.strictEqual(store.readBlob(dir, 'not-a-hash'), null);
  assert.ok(String(store.blobPath(dir, hex)).endsWith(path.join('blobs', hex)));
});

test('auditReadLines skips a corrupt trailing line; auditQuery filters', () => {
  const dir = tmpDir();
  store.auditAppend(dir, { type: 'letter.create', letterId: 'ltr_a' });
  store.auditAppend(dir, { type: 'address.verify', addressSha256: 'x' });
  // Simulate a crash mid-append: a truncated final line.
  fs.appendFileSync(path.join(dir, 'audit.log'), '{"type":"letter.create","letterId":"ltr_b');
  const lines = store.auditReadLines(dir);
  assert.strictEqual(lines.length, 2, 'the corrupt line is skipped, the rest survive');
  const creates = store.auditQuery(lines, (l) => l.type === 'letter.create');
  assert.strictEqual(creates.length, 1);
  assert.strictEqual(creates[0].letterId, 'ltr_a');
});

test('auditReadLines returns [] when there is no log yet', () => {
  assert.deepStrictEqual(store.auditReadLines(tmpDir()), []);
});

test('proxyAuditType classifies exactly the three captured calls', () => {
  assert.strictEqual(store.proxyAuditType('POST', '/v1/letters'), 'letter.create');
  assert.strictEqual(store.proxyAuditType('POST', '/v1/letters?foo=1'), 'letter.create');
  assert.strictEqual(store.proxyAuditType('GET', '/v1/letters'), null, 'listing is not captured');
  assert.strictEqual(store.proxyAuditType('GET', '/v1/letters/ltr_abc'), null, 'a single GET is not captured');
  assert.strictEqual(store.proxyAuditType('DELETE', '/v1/letters/ltr_abc123'), 'letter.cancel');
  assert.strictEqual(store.proxyAuditType('DELETE', '/v1/letters/not_an_id'), null);
  assert.strictEqual(store.proxyAuditType('POST', '/v1/us_verifications'), 'address.verify');
  assert.strictEqual(store.proxyAuditType('POST', '/v1/something_else'), null);
});

test('classifyProxyKeyEnv derives test/live from Basic auth and never returns the key', () => {
  const basic = (k) => 'Basic ' + Buffer.from(k + ':').toString('base64');
  assert.strictEqual(store.classifyProxyKeyEnv(basic('test_abc')), 'test');
  assert.strictEqual(store.classifyProxyKeyEnv(basic('live_abc')), 'live');
  assert.strictEqual(store.classifyProxyKeyEnv(basic('sk_unknown')), 'live', 'unknown prefix errs to live');
  assert.strictEqual(store.classifyProxyKeyEnv('Bearer whatever'), null, 'non-Basic yields no classification');
});

test('captureProxyEvent records a letter.create with a blob and no Authorization material', () => {
  const dir = tmpDir();
  const reqBuf = Buffer.from('--boundary multipart bytes--');
  const resp = Buffer.from(JSON.stringify({ id: 'ltr_capture1', object: 'letter' }));
  const reqHeaders = { 'idempotency-key': 'idem-123', 'x-pd-fingerprint': 'f'.repeat(64), 'x-pd-recipient-hash': 'a'.repeat(64) };
  const upstreamAuth = 'Basic ' + Buffer.from('live_secretkey:').toString('base64');
  store.captureProxyEvent(dir, 'letter.create', '/v1/letters', reqHeaders, upstreamAuth, reqBuf, 200, resp);

  const lines = store.auditReadLines(dir);
  assert.strictEqual(lines.length, 1);
  const ev = lines[0];
  assert.strictEqual(ev.type, 'letter.create');
  assert.strictEqual(ev.status, 200);
  assert.strictEqual(ev.letterId, 'ltr_capture1');
  assert.strictEqual(ev.idempotencyKey, 'idem-123');
  assert.strictEqual(ev.fingerprint, 'f'.repeat(64));
  assert.strictEqual(ev.recipientSha256, 'a'.repeat(64), 'X-PD-Recipient-Hash is captured for verification correlation');
  assert.strictEqual(ev.keyEnv, 'live');
  assert.strictEqual(ev.requestBlobSha256, store.sha256Hex(reqBuf));
  assert.strictEqual(ev.requestBytes, reqBuf.length);
  assert.deepStrictEqual(store.readBlob(dir, ev.requestBlobSha256), reqBuf, 'blob holds the exact request bytes');
  // Belt and suspenders: the serialized line must contain no key material.
  const serialized = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8');
  assert.ok(!serialized.includes('secretkey'), 'the Lob key must never appear in the log');
  assert.ok(!/authorization/i.test(serialized), 'no Authorization field is stored');
});

test('captureProxyEvent records a 422 failure with its status', () => {
  const dir = tmpDir();
  const resp = Buffer.from(JSON.stringify({ error: { message: 'send_date is invalid' } }));
  store.captureProxyEvent(dir, 'letter.create', '/v1/letters', {}, undefined, Buffer.from('x'), 422, resp);
  const ev = store.auditReadLines(dir)[0];
  assert.strictEqual(ev.status, 422);
  assert.strictEqual(ev.letterId, null, 'a failed create has no letter id');
  assert.ok(ev.response && ev.response.error, 'the failure response is recorded');
});

test('captureProxyEvent records cancel (letter id from path) and verify (address hash from body)', () => {
  const dir = tmpDir();
  store.captureProxyEvent(dir, 'letter.cancel', '/v1/letters/ltr_cancelme',
    {}, undefined, Buffer.alloc(0), 200, Buffer.from(JSON.stringify({ id: 'ltr_cancelme', deleted: true })));
  const verifyReq = Buffer.from(JSON.stringify({ primary_line: '185 Berry St', secondary_line: 'Ste 6100', city: 'San Francisco', state: 'CA', zip_code: '94107' }));
  store.captureProxyEvent(dir, 'address.verify', '/v1/us_verifications',
    {}, undefined, verifyReq, 200, Buffer.from(JSON.stringify({ deliverability: 'deliverable' })));

  const lines = store.auditReadLines(dir);
  const cancel = lines.find((l) => l.type === 'letter.cancel');
  assert.strictEqual(cancel.letterId, 'ltr_cancelme');
  const verify = lines.find((l) => l.type === 'address.verify');
  assert.strictEqual(verify.addressSha256,
    store.addressHash({ line1: '185 Berry St', line2: 'Ste 6100', city: 'San Francisco', state: 'CA', zip: '94107' }),
    'verify event address hash correlates to the same normalized recipient');
});
