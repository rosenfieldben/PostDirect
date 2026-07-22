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
  assert.strictEqual(mode(path.join(dir, 'exports')), 0o700, 'exports dir 0700');
  assert.strictEqual(mode(path.join(dir, 'audit.log')), 0o600, 'audit.log created 0600');
  assert.strictEqual(mode(path.join(dir, 'blobs', blobHex)), 0o600, 'blob file created 0600');
});

test('ensureDataDir tolerates a chmod failure (a mounted volume it does not own) instead of crashing', () => {
  // A unit test cannot chown to another uid without root, so simulate the EPERM a
  // volume owned by a different user would raise by stubbing fs.chmodSync. The
  // pre-fix code let that EPERM escape and turned a writable-but-unowned mount
  // into a fatal boot; it must now stay usable and warn instead.
  const dir = tmpDir();
  fs.chmodSync(dir, 0o755); // a looser, pre-existing mount we then cannot re-mode
  const realChmod = fs.chmodSync;
  const realErr = console.error;
  const warnings = [];
  console.error = (m) => { warnings.push(String(m)); };
  fs.chmodSync = () => { const e = new Error('operation not permitted'); e.code = 'EPERM'; throw e; };
  let r;
  try {
    r = store.ensureDataDir(dir);
  } finally {
    fs.chmodSync = realChmod;
    console.error = realErr;
  }
  assert.strictEqual(r.ok, true, 'a dir it cannot chmod is still usable, not a fatal boot error');
  assert.ok(warnings.some((w) => /could not tighten/.test(w) && /0755/.test(w)),
    'it warns loudly that the still-loose dir could not be tightened');
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
  assert.ok(fs.existsSync(path.join(dir, 'exports')), 'exports/ created');
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

test('auditAppend stamps a monotonic seq and a prev chain, first prev is genesis', () => {
  const dir = tmpDir();
  store.auditAppend(dir, { type: 'a' }, 1000);
  store.auditAppend(dir, { type: 'b' }, 2000);
  store.auditAppend(dir, { type: 'c' }, 3000);
  const lines = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  assert.deepStrictEqual(lines.map((l) => l.seq), [1, 2, 3], 'seq is 1-based and monotonic');
  assert.strictEqual(lines[0].prev, '0'.repeat(64), 'the first line points at the genesis 64 zeros');
  // Each line's prev is the sha256 of the PREVIOUS line's raw bytes (its own
  // newline excluded), which is the exact chaining a verifier re-derives.
  const rawLines = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8').split('\n').filter(Boolean);
  assert.strictEqual(lines[1].prev, store.sha256Hex(Buffer.from(rawLines[0], 'utf8')));
  assert.strictEqual(lines[2].prev, store.sha256Hex(Buffer.from(rawLines[1], 'utf8')));
});

test('auditVerifyChain reports ok with the head hash for a clean chained log', () => {
  const dir = tmpDir();
  store.auditAppend(dir, { type: 'a' }, 1000);
  store.auditAppend(dir, { type: 'b' }, 2000);
  const v = store.auditVerifyChain(dir);
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.checkedLines, 2, 'both chained lines verified');
  assert.strictEqual(v.legacyLines, 0);
  assert.strictEqual(v.corruptLines, 0);
  assert.strictEqual(v.firstBreakSeq, null);
  // head is the sha256 of the LAST line's raw bytes: the anchorable commitment.
  const rawLines = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8').split('\n').filter(Boolean);
  assert.strictEqual(v.head, store.sha256Hex(Buffer.from(rawLines[rawLines.length - 1], 'utf8')));
});

test('auditVerifyChain: an empty/absent log verifies ok with the genesis head', () => {
  const v = store.auditVerifyChain(tmpDir());
  assert.deepStrictEqual(v, { ok: true, checkedLines: 0, legacyLines: 0, corruptLines: 0, firstBreakSeq: null, head: '0'.repeat(64) });
});

test('auditVerifyChain: tampering a middle line breaks the chain at the NEXT sequence', () => {
  const dir = tmpDir();
  store.auditAppend(dir, { type: 'a', n: 1 }, 1000);
  store.auditAppend(dir, { type: 'b', n: 2 }, 2000);
  store.auditAppend(dir, { type: 'c', n: 3 }, 3000);
  // Rewrite line 2 (seq 2) in place, preserving its own seq/prev. Its bytes now
  // differ, so line 3's recorded prev (the hash of the ORIGINAL line 2) no longer
  // matches: the break surfaces at seq 3, the first line whose predecessor moved.
  const lines = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8').split('\n').filter(Boolean);
  const obj = JSON.parse(lines[1]); obj.n = 999; lines[1] = JSON.stringify(obj);
  fs.writeFileSync(path.join(dir, 'audit.log'), lines.join('\n') + '\n');
  const realErr = console.error;
  const warnings = [];
  console.error = (m) => { warnings.push(String(m)); };
  let v;
  try { v = store.auditVerifyChain(dir); } finally { console.error = realErr; }
  assert.strictEqual(v.ok, false, 'a tampered line is detected');
  assert.strictEqual(v.firstBreakSeq, 3, 'the break surfaces at the line after the altered one');
  assert.ok(warnings.some((w) => /AUDIT CHAIN BROKEN/.test(w) && /seq 3/.test(w)), 'it logs loudly on a break');
});

test('auditVerifyChain: a legacy prefix (no seq/prev) verifies and is counted, chained lines after it still check', () => {
  const dir = tmpDir();
  store.ensureDataDir(dir);
  // Two pre-chain lines, exactly as an older build wrote them: no seq, no prev.
  fs.writeFileSync(path.join(dir, 'audit.log'),
    JSON.stringify({ ts: '2026-01-01T00:00:00.000Z', type: 'letter.create', letterId: 'ltr_legacy1' }) + '\n' +
    JSON.stringify({ ts: '2026-01-02T00:00:00.000Z', type: 'letter.cancel', letterId: 'ltr_legacy1' }) + '\n');
  // Now append through auditAppend: it re-scans the tail (no cache for this path),
  // so the new line's seq continues past the legacy count and its prev commits to
  // the last legacy line's bytes.
  store.auditAppend(dir, { type: 'address.verify', addressSha256: 'x' }, 3000);
  const v = store.auditVerifyChain(dir);
  assert.strictEqual(v.legacyLines, 2, 'both pre-chain lines are counted as legacy');
  assert.strictEqual(v.checkedLines, 1, 'the appended chained line verified against the legacy prefix');
  assert.strictEqual(v.ok, true, 'a legacy prefix followed by a valid chain is not a break');
  // The appended line carries seq 3 (position over the whole file) and its prev
  // is the hash of the last legacy line, so the chain commits to the prefix.
  const lines = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8').split('\n').filter(Boolean);
  const appended = JSON.parse(lines[2]);
  assert.strictEqual(appended.seq, 3, 'seq counts the whole file, legacy prefix included');
  assert.strictEqual(appended.prev, store.sha256Hex(Buffer.from(lines[1], 'utf8')));
});

test('auditVerifyChain: a corrupt line is reported as corruptLines and its bytes still advance the chain', () => {
  const dir = tmpDir();
  store.auditAppend(dir, { type: 'a' }, 1000);
  // Inject an unparseable line by hand, then confirm both the parse count (via
  // auditReadStats) and the chain result (via auditVerifyChain) report it. This
  // is the P3-A corrupt-line fixture shape, now cross-checked against the chain.
  fs.appendFileSync(path.join(dir, 'audit.log'), '{ this is not json\n');
  store.auditAppend(dir, { type: 'c' }, 3000);  // re-scans past the corrupt line
  const realErr = console.error;
  console.error = () => {};  // silence the loud corruption/break warnings for this test
  let stats, v;
  try {
    stats = store.auditReadStats(dir);
    v = store.auditVerifyChain(dir);
  } finally { console.error = realErr; }
  assert.strictEqual(stats.corruptCount, 1, 'the parse layer counts the corrupt line');
  assert.strictEqual(v.corruptLines, 1, 'the chain verifier counts the corrupt line');
  // The corrupt line still advanced the running hash, so the line appended after
  // it (whose prev was taken from the corrupt line bytes) verifies cleanly.
  assert.strictEqual(v.ok, true, 'the chain across the corrupt line is intact');
  assert.strictEqual(v.checkedLines, 2, 'the two chained lines both verify');
});

test('auditAppend continues the chain after a same-process re-scan (stale tail cache)', () => {
  const dir = tmpDir();
  store.auditAppend(dir, { type: 'a' }, 1000);
  store.auditAppend(dir, { type: 'b' }, 2000);
  // Truncate the file behind the cache's back to a single line: the on-disk size
  // no longer matches the cached tail, so the next append must re-scan and chain
  // onto the CURRENT last line, not the stale cached one.
  const lines = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8').split('\n').filter(Boolean);
  fs.writeFileSync(path.join(dir, 'audit.log'), lines[0] + '\n');
  const realErr = console.error;
  const warnings = [];
  console.error = (m) => { warnings.push(String(m)); };
  try { store.auditAppend(dir, { type: 'c' }, 3000); } finally { console.error = realErr; }
  assert.ok(warnings.some((w) => /AUDIT TAIL CACHE STALE/.test(w)), 'the size mismatch is logged loudly');
  const after = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  assert.deepStrictEqual(after.map((l) => l.seq), [1, 2], 'the re-scan chained onto the truncated file (seq 1 then 2)');
  assert.strictEqual(store.auditVerifyChain(dir).ok, true, 'the resulting chain verifies');
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

test('captureProxyEvent records a letter.create linked to its intent, with a blob and no Authorization material', () => {
  const dir = tmpDir();
  const reqBuf = Buffer.from('--boundary multipart bytes--');
  const resp = Buffer.from(JSON.stringify({ id: 'ltr_capture1', object: 'letter' }));
  const reqHeaders = { 'idempotency-key': 'idem-123', 'x-pd-fingerprint': 'f'.repeat(64), 'x-pd-recipient-hash': 'a'.repeat(64) };
  const upstreamAuth = 'Basic ' + Buffer.from('live_secretkey:').toString('base64');
  // The real flow writes the intent (which stores the request-body blob) BEFORE
  // Lob is contacted; the outcome capture then references that blob and links
  // back to the intent by id. Mirror that order here.
  const intentId = store.writeSendIntent(dir, { lobPath: '/v1/letters', reqHeaders, reqBuf }, 1000);
  store.captureProxyEvent(dir, 'letter.create', '/v1/letters', reqHeaders, upstreamAuth, reqBuf, 200, resp, intentId);

  const lines = store.auditReadLines(dir);
  assert.strictEqual(lines.length, 2, 'the intent line and the outcome line');
  const ev = lines.find((l) => l.type === 'letter.create');
  assert.strictEqual(ev.status, 200);
  assert.strictEqual(ev.letterId, 'ltr_capture1');
  assert.strictEqual(ev.intentId, intentId, 'the outcome links back to the write-ahead intent');
  assert.strictEqual(ev.idempotencyKey, 'idem-123');
  assert.strictEqual(ev.fingerprint, 'f'.repeat(64));
  assert.strictEqual(ev.recipientSha256, 'a'.repeat(64), 'X-PD-Recipient-Hash is captured for verification correlation');
  assert.strictEqual(ev.keyEnv, 'live');
  assert.strictEqual(ev.requestBlobSha256, store.sha256Hex(reqBuf));
  assert.strictEqual(ev.requestBytes, reqBuf.length);
  // The blob was stored at intent time (not by the capture), and still holds the
  // exact request bytes the outcome references.
  assert.deepStrictEqual(store.readBlob(dir, ev.requestBlobSha256), reqBuf, 'blob holds the exact request bytes');
  // The outcome resolves the intent: nothing left in the reconciliation worklist.
  assert.deepStrictEqual(store.unresolvedIntents(dir), [], 'a recorded outcome resolves the intent');
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

test('writeSendIntent stores the request blob and records a send.intent that unresolvedIntents surfaces', () => {
  const dir = tmpDir();
  const reqBuf = Buffer.from('the exact bytes we are about to send to Lob');
  const headers = { 'idempotency-key': 'idem-x', 'x-pd-fingerprint': 'f'.repeat(64), 'x-pd-recipient-hash': 'r'.repeat(64) };
  const intentId = store.writeSendIntent(dir, { lobPath: '/v1/letters', reqHeaders: headers, reqBuf }, 1000);
  assert.match(intentId, store.INTENT_ID_RE, 'a v4 UUID intent id is returned');
  const intent = store.auditReadLines(dir).find((l) => l.type === 'send.intent');
  assert.strictEqual(intent.intentId, intentId);
  assert.strictEqual(intent.lobPath, '/v1/letters');
  assert.strictEqual(intent.idempotencyKey, 'idem-x');
  assert.strictEqual(intent.fingerprint, 'f'.repeat(64));
  assert.strictEqual(intent.recipientHash, 'r'.repeat(64));
  assert.strictEqual(intent.requestSha256, store.sha256Hex(reqBuf), 'the intent commits to the request bytes');
  assert.strictEqual(intent.requestBlob, intent.requestSha256, 'requestBlob is the content-addressed key');
  // The blob is stored at intent time (this is the ONLY place it is written now).
  assert.deepStrictEqual(store.readBlob(dir, intent.requestBlob), reqBuf);
  // With no outcome yet, the intent is unresolved: it is the reconciliation list.
  const unresolved = store.unresolvedIntents(dir);
  assert.strictEqual(unresolved.length, 1);
  assert.strictEqual(unresolved[0].intentId, intentId);
  assert.strictEqual(unresolved[0].requestSha256, intent.requestSha256);
});

test('unresolvedIntents: an outcome OR a manual resolution clears an intent', () => {
  const dir = tmpDir();
  // Three intents. One resolved by a recorded outcome, one by a manual
  // resolution, one left dangling.
  const byOutcome = store.writeSendIntent(dir, { lobPath: '/v1/letters', reqHeaders: {}, reqBuf: Buffer.from('outcome-body') }, 1000);
  const byResolution = store.writeSendIntent(dir, { lobPath: '/v1/letters', reqHeaders: {}, reqBuf: Buffer.from('resolution-body') }, 2000);
  const dangling = store.writeSendIntent(dir, { lobPath: '/v1/letters', reqHeaders: {}, reqBuf: Buffer.from('dangling-body') }, 3000);
  // A recorded letter.create carrying the intentId resolves the first.
  store.auditAppend(dir, { type: 'letter.create', status: 200, letterId: 'ltr_x', intentId: byOutcome }, 4000);
  // A manual resolution resolves the second.
  store.appendIntentResolution(dir, byResolution, { resolution: 'not_sent', note: 'checked Lob, nothing there' }, 5000);
  const ids = store.unresolvedIntents(dir).map((i) => i.intentId);
  assert.deepStrictEqual(ids, [dangling], 'only the intent with neither an outcome nor a resolution remains');
});

test('appendIntentResolution validates input and refuses unknown intents', () => {
  const dir = tmpDir();
  const intentId = store.writeSendIntent(dir, { lobPath: '/v1/letters', reqHeaders: {}, reqBuf: Buffer.from('body') }, 1000);
  // Bad resolution value.
  let r = store.appendIntentResolution(dir, intentId, { resolution: 'bogus' }, 2000);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 400);
  // Bad letterId format.
  r = store.appendIntentResolution(dir, intentId, { resolution: 'accepted', letterId: 'not-a-letter' }, 2000);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 400);
  // Unknown intent id (well-formed but never written).
  r = store.appendIntentResolution(dir, '00000000-0000-4000-8000-000000000000', { resolution: 'unknown' }, 2000);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.status, 404);
  // Valid: appends a send.intent.resolved line and clears the worklist.
  r = store.appendIntentResolution(dir, intentId, { resolution: 'accepted', letterId: 'ltr_real1', note: 'found it at Lob' }, 3000);
  assert.strictEqual(r.ok, true);
  const resolved = store.auditReadLines(dir).find((l) => l.type === 'send.intent.resolved');
  assert.strictEqual(resolved.intentId, intentId);
  assert.strictEqual(resolved.resolution, 'accepted');
  assert.strictEqual(resolved.letterId, 'ltr_real1');
  assert.strictEqual(resolved.note, 'found it at Lob');
  assert.deepStrictEqual(store.unresolvedIntents(dir), [], 'the resolution clears the intent');
});
