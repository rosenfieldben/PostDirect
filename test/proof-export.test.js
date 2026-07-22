'use strict';
// Item 2: proof package export. Two layers of test:
//  (1) buildProofPackage exercised hermetically with injected fetchers (no
//      network), its ZIP validated by an INDEPENDENT reader below so the writer
//      is never validated only by itself.
//  (2) the /api/proof/:letterId endpoint through a listening server + a stub
//      upstream, for auth, malformed-id rejection, and the real fetch wiring.
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const zlib = require('node:zlib');

const test = require('node:test');
const assert = require('node:assert');

// ── Independent ZIP reader (parses EOCD + central directory, verifies CRC-32
// of each entry against the extracted STORED bytes). Deliberately shares no
// code with server.js's writer. ──
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  return (c ^ 0xffffffff) >>> 0;
}
function readZip(buf) {
  // Find EOCD by scanning backward for its signature.
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  assert.notStrictEqual(eocd, -1, 'EOCD not found');
  const total = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  let p = buf.readUInt32LE(eocd + 14);
  const cdEnd = p + cdSize;
  const entries = {};
  for (let n = 0; n < total; n++) {
    assert.strictEqual(buf.readUInt32LE(p), 0x02014b50, 'central header signature');
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const compSize = buf.readUInt32LE(p + 20);
    const uncompSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const name = buf.slice(p + 46, p + 46 + nameLen).toString('utf8');
    // Parse the local header to find the data.
    assert.strictEqual(buf.readUInt32LE(localOff), 0x04034b50, 'local header signature');
    const lNameLen = buf.readUInt16LE(localOff + 26);
    const lExtraLen = buf.readUInt16LE(localOff + 28);
    const dataStart = localOff + 30 + lNameLen + lExtraLen;
    let data = buf.slice(dataStart, dataStart + compSize);
    assert.strictEqual(method, 0, 'store-only, no compression, for ' + name);
    assert.strictEqual(data.length, uncompSize, 'stored size matches for ' + name);
    assert.strictEqual(crc32(data) >>> 0, crc >>> 0, 'CRC-32 matches for ' + name);
    entries[name] = data;
    p += 46 + nameLen + extraLen + commentLen;
  }
  assert.ok(p <= cdEnd + 0, 'walked exactly the central directory');
  return entries;
}

// Sanity check the independent reader against a known-good archive from zlib's
// gzip is not enough (that is not ZIP), so instead validate the reader against
// our writer for a trivial input AND cross-check CRC against zlib.crc32 when
// available.
test('independent reader agrees with zlib.crc32', () => {
  const b = Buffer.from('crc cross-check bytes');
  if (typeof zlib.crc32 === 'function') {
    assert.strictEqual(crc32(b) >>> 0, zlib.crc32(b) >>> 0, 'reader CRC matches node zlib.crc32');
  }
});

// server.js reads credentials and the upstream target at MODULE LOAD, and the
// stub's port is not known until it is listening, so store is required inside
// the before hook (after env is set), and every test runs after that hook.
let store, DATA_DIR;

function seedLetter(dir, id, opts) {
  opts = opts || {};
  const reqBytes = Buffer.from(opts.reqBytes || ('MULTIPART REQUEST BYTES for ' + id));
  const blobHash = store.blobStore(dir, reqBytes);
  const response = opts.response || {
    id, object: 'letter', mail_type: 'usps_first_class', color: false, double_sided: true,
    to: { name: 'John Doe', address_line1: '456 Oak Ave', address_line2: '', address_city: 'Chicago', address_state: 'IL', address_zip: '60601' },
  };
  store.auditAppend(dir, {
    type: 'letter.create', status: 200, letterId: id, requestBlobSha256: blobHash,
    requestBytes: reqBytes.length, idempotencyKey: 'idem-' + id, fingerprint: 'f'.repeat(64),
    keyEnv: 'live', response,
  });
  // A correlated verification for the same recipient.
  store.auditAppend(dir, {
    type: 'address.verify', status: 200,
    addressSha256: store.addressHash({ line1: '456 Oak Ave', line2: '', city: 'Chicago', state: 'IL', zip: '60601' }),
    keyEnv: 'live', response: { deliverability: 'deliverable' },
  });
  return { reqBytes, blobHash, response };
}

test('buildProofPackage: seeded letter yields a valid ZIP with all seven entries and matching manifest hashes', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-proof-ok-'));
  const seed = seedLetter(dir, 'ltr_ok1');
  const pdfBytes = Buffer.from('%PDF-1.4 rendered letter bytes');
  const pkg = await store.buildProofPackage(dir, 'ltr_ok1', {
    now: () => Date.parse('2026-07-18T15:00:00Z'),
    fetchLetter: async () => ({ ok: true, letter: { id: 'ltr_ok1', url: 'https://lob-assets.com/letters/ltr_ok1.pdf?sig=x', tracking_events: [{ name: 'Mailed', time: '2026-07-18T00:00:00Z' }] } }),
    fetchAsset: async () => ({ ok: true, bytes: pdfBytes }),
  });

  const entries = readZip(pkg.zip);
  const names = Object.keys(entries).sort();
  assert.deepStrictEqual(names, [
    'audit.jsonl', 'creation-response.json', 'manifest.json', 'rendered.pdf',
    'request-body.bin', 'tracking.json', 'verifications.json',
  ], 'all seven entries present');

  // Exact stored bytes round-trip.
  assert.deepStrictEqual(entries['request-body.bin'], seed.reqBytes);
  assert.deepStrictEqual(entries['rendered.pdf'], pdfBytes);

  // Manifest inventory hashes match the actual entry bytes.
  const manifest = JSON.parse(entries['manifest.json'].toString('utf8'));
  assert.strictEqual(manifest.letterId, 'ltr_ok1');
  assert.strictEqual(manifest.keyEnv, 'live');
  assert.strictEqual(manifest.fingerprint, 'f'.repeat(64));
  assert.deepStrictEqual(manifest.missing, [], 'nothing missing on the happy path');
  assert.strictEqual(manifest.complete, true, 'a full bundle is marked complete');
  assert.strictEqual(manifest.hasLocalRecord, true, 'the letter.create record is present');
  assert.strictEqual(manifest.auditCorruptLines, 0, 'a clean seeded log reports zero corrupt audit lines');
  assert.strictEqual(manifest.pdfSha256, store.sha256Hex(pdfBytes), 'manifest links the letter to the archived render');
  // The manifest carries the tamper-evidence result for the whole log the bundle
  // was drawn from. The seeded log is fully chained (auditAppend wrote seq/prev),
  // so the chain is intact with no legacy or broken lines. head is the anchorable
  // commitment; it is the chain verifier's head, computed BEFORE this export's own
  // proof.export line was appended, so it commits to history as of export time.
  assert.ok(manifest.chain, 'manifest carries the chain result');
  assert.strictEqual(manifest.chain.ok, true, 'the seeded chain is intact');
  assert.strictEqual(manifest.chain.legacyLines, 0, 'auditAppend-written lines are all chained');
  assert.strictEqual(manifest.chain.firstBreakSeq, null, 'no break in a clean chain');
  assert.match(manifest.chain.head, /^[0-9a-f]{64}$/, 'head is a sha256 hex commitment');

  // Item 3: the finished bundle is persisted under exports/, named by letter id
  // and the colon-stripped generatedAt, at 0600, and the persisted bytes ARE the
  // bundle. The manifest and the return value both name that path.
  assert.strictEqual(manifest.packagePath, 'exports/ltr_ok1-2026-07-18T15-00-00.000Z.zip');
  assert.strictEqual(pkg.packagePath, manifest.packagePath, 'the return value names the same path');
  const persisted = fs.readFileSync(path.join(dir, manifest.packagePath));
  assert.strictEqual(store.sha256Hex(persisted), pkg.packageSha256, 'the persisted file is the exact bundle');
  assert.strictEqual(fs.statSync(path.join(dir, manifest.packagePath)).mode & 0o777, 0o600, 'the export is persisted 0600');
  for (const f of manifest.files) {
    assert.ok(entries[f.name], 'inventory names a real entry: ' + f.name);
    assert.strictEqual(store.sha256Hex(entries[f.name]), f.sha256, 'manifest hash matches ' + f.name);
    assert.strictEqual(entries[f.name].length, f.bytes, 'manifest size matches ' + f.name);
  }
  // The rendered PDF was archived as a content-addressed blob.
  assert.deepStrictEqual(store.readBlob(dir, store.sha256Hex(pdfBytes)), pdfBytes);

  // verifications.json correlates the seeded verify event by address hash.
  const verifs = JSON.parse(entries['verifications.json'].toString('utf8'));
  assert.strictEqual(verifs.length, 1);
  assert.strictEqual(verifs[0].type, 'address.verify');

  // The export itself is an audit event.
  const exportEvents = store.auditReadLines(dir).filter((l) => l.type === 'proof.export');
  assert.strictEqual(exportEvents.length, 1);
  assert.strictEqual(exportEvents[0].packageSha256, pkg.packageSha256);
  assert.strictEqual(exportEvents[0].packagePath, manifest.packagePath, 'the export event names the persisted path');
  assert.strictEqual(exportEvents[0].auditCorruptLines, 0, 'the export event records the corrupt-line count');
  assert.strictEqual(exportEvents[0].pdfSha256, store.sha256Hex(pdfBytes), 'the export event links the archived render');
  assert.deepStrictEqual(exportEvents[0].fetched.sort(), ['rendered.pdf', 'tracking.json']);
});

test('buildProofPackage: a 404 on the rendered PDF still succeeds and records the miss', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-proof-miss-'));
  seedLetter(dir, 'ltr_miss1');
  const pkg = await store.buildProofPackage(dir, 'ltr_miss1', {
    now: () => Date.parse('2026-07-18T15:00:00Z'),
    fetchLetter: async () => ({ ok: true, letter: { id: 'ltr_miss1', url: 'https://lob-assets.com/letters/ltr_miss1.pdf?sig=x' } }),
    fetchAsset: async () => ({ ok: false, status: 404 }),
  });
  const entries = readZip(pkg.zip);
  assert.ok(!entries['rendered.pdf'], 'the missing PDF is not an entry');
  assert.ok(entries['manifest.json'], 'the package still builds');
  const manifest = JSON.parse(entries['manifest.json'].toString('utf8'));
  const miss = manifest.missing.find((m) => m.name === 'rendered.pdf');
  assert.ok(miss, 'manifest records the rendered.pdf miss');
  assert.match(miss.reason, /404/, 'the reason names the status');
  assert.strictEqual(manifest.pdfSha256, null, 'no pdfSha256 when the render could not be fetched');
  assert.strictEqual(manifest.complete, false, 'a partial bundle is marked incomplete');
  assert.strictEqual(manifest.hasLocalRecord, true, 'the local record is still present (only the live PDF is missing)');
  // Everything the manifest DOES list must still hash-match.
  for (const f of manifest.files) {
    assert.strictEqual(store.sha256Hex(entries[f.name]), f.sha256, 'manifest hash matches ' + f.name);
  }
});

test('buildProofPackage: a letter with NO local record is marked hasLocalRecord=false and incomplete', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-proof-nolocal-'));
  // Never seeded: no letter.create in the store, e.g. a letter created via
  // another tool but visible in the Lob account. Lob still serves the object.
  const pkg = await store.buildProofPackage(dir, 'ltr_external1', {
    now: () => Date.parse('2026-07-18T15:00:00Z'),
    fetchLetter: async () => ({ ok: true, letter: { id: 'ltr_external1', url: 'https://lob-assets.com/letters/ltr_external1.pdf' } }),
    fetchAsset: async () => ({ ok: true, bytes: Buffer.from('%PDF external') }),
  });
  const manifest = JSON.parse(readZip(pkg.zip)['manifest.json'].toString('utf8'));
  assert.strictEqual(manifest.hasLocalRecord, false, 'no letter.create record for this id');
  assert.strictEqual(manifest.complete, false, 'the core request/response are missing');
  const missNames = manifest.missing.map((m) => m.name);
  assert.ok(missNames.includes('request-body.bin'), 'request bytes flagged missing');
  assert.ok(missNames.includes('creation-response.json'), 'creation response flagged missing');
  // The proof.export audit event carries the same signals.
  const ev = store.auditReadLines(dir).filter((l) => l.type === 'proof.export').pop();
  assert.strictEqual(ev.complete, false);
  assert.strictEqual(ev.hasLocalRecord, false);
});

// ── Endpoint-level: auth, malformed id, and full wiring through a stub. ──
let upstream, upstreamPort, server, port;

test.before(() => new Promise((resolve) => {
  upstream = http.createServer((req, res) => {
    if (req.method === 'GET' && /^\/v1\/letters\/ltr_/.test(req.url)) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id: 'ltr_endpoint1', url: 'http://127.0.0.1:' + upstreamPort + '/rendered/ltr_endpoint1.pdf', tracking_events: [] }));
      return;
    }
    if (req.method === 'GET' && req.url.indexOf('/rendered/') === 0) {
      res.writeHead(200, { 'Content-Type': 'application/pdf' });
      res.end(Buffer.from('%PDF endpoint rendered'));
      return;
    }
    res.writeHead(404); res.end();
  });
  upstream.listen(0, '127.0.0.1', () => {
    upstreamPort = upstream.address().port;
    DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-proof-'));
    process.env.PD_LOB_UPSTREAM = 'http://127.0.0.1:' + upstreamPort;
    process.env.PD_DATA_DIR = DATA_DIR;
    process.env.PD_SECRET = 'proof-itest-secret-fixed-0123456789';
    process.env.PD_USERNAME = 'itest-user';
    process.env.PD_PASSWORD = 'itest-password';
    store = require('../server.js');
    server = store.server;
    server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
  });
}));
test.after(() => new Promise((resolve) => server.close(() => upstream.close(resolve))));

function request(opts) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, agent: false, ...opts }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    r.on('error', reject);
    r.end();
  });
}
async function login() {
  const r = await new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, agent: false, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }, (res) => {
      res.resume(); res.on('end', () => resolve(res));
    });
    req.on('error', reject); req.write('username=itest-user&password=itest-password'); req.end();
  });
  return String(r.headers['set-cookie']).split(';')[0];
}

test('unauthenticated proof export redirects to /login (consistent with other routes)', async () => {
  const r = await request({ path: '/api/proof/ltr_endpoint1', method: 'GET' });
  assert.strictEqual(r.status, 302);
  assert.strictEqual(r.headers.location, '/login');
});

test('a malformed letter id is rejected 400 before any store access', async () => {
  const cookie = await login();
  for (const bad of ['/api/proof/not-an-id', '/api/proof/ltr_', '/api/proof/..%2f..%2fetc', '/api/proof/ltr_abc$(x)']) {
    const r = await request({ path: bad, method: 'GET', headers: { Cookie: cookie } });
    assert.strictEqual(r.status, 400, bad + ' must be 400');
  }
});

test('authenticated export streams a valid ZIP the independent reader accepts', async () => {
  seedLetter(DATA_DIR, 'ltr_endpoint1');
  const cookie = await login();
  const r = await request({ path: '/api/proof/ltr_endpoint1', method: 'GET', headers: { Cookie: cookie } });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.headers['content-type'], 'application/zip');
  assert.match(String(r.headers['content-disposition']), /filename="proof-ltr_endpoint1-\d{4}-\d{2}-\d{2}\.zip"/);
  assert.strictEqual(r.headers['x-pd-proof-complete'], 'true', 'completeness advertised in a header');
  assert.strictEqual(r.headers['x-pd-proof-has-local-record'], 'true');
  const entries = readZip(r.body);
  assert.ok(entries['manifest.json'] && entries['rendered.pdf'] && entries['request-body.bin']);
  const manifest = JSON.parse(entries['manifest.json'].toString('utf8'));
  assert.strictEqual(manifest.letterId, 'ltr_endpoint1');
  assert.deepStrictEqual(entries['rendered.pdf'], Buffer.from('%PDF endpoint rendered'), 'rendered PDF fetched through the stub');
});

test('endpoint advertises an incomplete proof in headers when there is no local record', async () => {
  const cookie = await login();
  // ltr_endpoint2 has no seeded letter.create; the stub still serves the object.
  const r = await request({ path: '/api/proof/ltr_endpoint2', method: 'GET', headers: { Cookie: cookie } });
  assert.strictEqual(r.status, 200, 'a partial proof still downloads');
  assert.strictEqual(r.headers['x-pd-proof-complete'], 'false');
  assert.strictEqual(r.headers['x-pd-proof-has-local-record'], 'false');
  assert.match(String(r.headers['x-pd-proof-missing']), /request-body\.bin/);
});
