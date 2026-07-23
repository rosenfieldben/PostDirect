'use strict';
// Integration test for item 1: capture happens IN THE PROXY against a real stub
// upstream, writing to a temp PD_DATA_DIR. The stub, the data dir, and all
// credentials/upstream are set BEFORE requiring server.js (resolved at load).
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const test = require('node:test');
const assert = require('node:assert');

let upstream, upstreamPort, lastCreateBody = null;
let server, port, DATA_DIR;
// Set by the stub each time it receives a create: the send.intent lines already
// on disk AT THAT MOMENT. Because writeSendIntent runs synchronously (and
// fsyncs) before the proxy writes any bytes upstream, the intent must already be
// durable by the time the stub sees the request. This is the write-AHEAD proof.
let intentPresentAtCreateHit = null;

test.before(() => new Promise((resolve) => {
  upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      if (req.method === 'POST' && req.url === '/v1/letters') {
        lastCreateBody = body;
        // Read the durable log as it stands right now, before we answer: the
        // intent for THIS send must already be recorded.
        const priorLines = require('../server.js').auditReadLines(DATA_DIR);
        intentPresentAtCreateHit = priorLines.filter((l) => l.type === 'send.intent').length;
        // Echo an invalid-option 422 when the marker is present, else 200 OK.
        if (body.toString('latin1').indexOf('FORCE_422') !== -1) {
          res.writeHead(422, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'send_date is invalid' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'ltr_stub123', object: 'letter', to: { name: 'A' } }));
        return;
      }
      if (req.method === 'DELETE' && /^\/v1\/letters\/ltr_/.test(req.url)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ id: 'ltr_stub123', deleted: true }));
        return;
      }
      if (req.method === 'POST' && req.url === '/v1/us_verifications') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ deliverability: 'deliverable' }));
        return;
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'not found' } }));
    });
  });
  upstream.listen(0, '127.0.0.1', () => {
    upstreamPort = upstream.address().port;
    DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-capture-'));
    process.env.PD_LOB_UPSTREAM = 'http://127.0.0.1:' + upstreamPort;
    process.env.PD_DATA_DIR = DATA_DIR;
    process.env.PD_SECRET = 'capture-itest-secret-fixed-0123456789';
    process.env.PD_USERNAME = 'itest-user';
    process.env.PD_PASSWORD = 'itest-password';
    server = require('../server.js').server;
    server.listen(0, '127.0.0.1', () => { port = server.address().port; resolve(); });
  });
}));

test.after(() => new Promise((resolve) => server.close(() => upstream.close(resolve))));

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, agent: false, ...opts }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

async function login() {
  const r = await request(
    { path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
    'username=itest-user&password=itest-password'
  );
  return String(r.headers['set-cookie']).split(';')[0];
}

function readLog() {
  const store = require('../server.js');
  return store.auditReadLines(DATA_DIR);
}

const clientKeyHeader = { 'Authorization': 'Basic ' + Buffer.from('test_clientkey:').toString('base64') };

test('POST /v1/letters writes the intent BEFORE contacting Lob, then a linked letter.create', async () => {
  const cookie = await login();
  const multipart = 'RAW-MULTIPART-BODY-BYTES-primary';
  const store = require('../server.js');
  const before = readLog().length;
  const intentsBefore = readLog().filter((l) => l.type === 'send.intent').length;
  const r = await request({
    path: '/api/lob/v1/letters', method: 'POST',
    headers: { ...clientKeyHeader, Cookie: cookie, 'Content-Type': 'multipart/form-data; boundary=x',
      'Idempotency-Key': 'idem-capture-1', 'X-PD-Fingerprint': 'a'.repeat(64), 'X-PD-Recipient-Hash': 'b'.repeat(64) },
  }, multipart);
  assert.strictEqual(r.status, 200);
  assert.ok(r.body.includes('ltr_stub123'), 'client still receives the upstream response');

  // The write-ahead proof: by the time the stub received this create, the intent
  // for it was already durable on disk (one more than before this request).
  assert.strictEqual(intentPresentAtCreateHit, intentsBefore + 1,
    'the send.intent was on disk before the stub ever saw the request');

  const lines = readLog();
  assert.strictEqual(lines.length, before + 2, 'two new lines: the intent, then the outcome');
  const intent = lines[before];
  const ev = lines[before + 1];
  // The intent: written first, records what we were about to send.
  assert.strictEqual(intent.type, 'send.intent');
  assert.match(intent.intentId, store.INTENT_ID_RE);
  assert.strictEqual(intent.lobPath, '/v1/letters');
  assert.strictEqual(intent.idempotencyKey, 'idem-capture-1');
  assert.strictEqual(intent.fingerprint, 'a'.repeat(64));
  assert.strictEqual(intent.recipientHash, 'b'.repeat(64));
  assert.strictEqual(intent.requestSha256, store.sha256Hex(Buffer.from(multipart)), 'intent commits to the request bytes');
  assert.strictEqual(intent.requestBlob, intent.requestSha256);
  // The outcome: written after Lob answered, linked back to the intent.
  assert.strictEqual(ev.type, 'letter.create');
  assert.strictEqual(ev.status, 200);
  assert.strictEqual(ev.letterId, 'ltr_stub123');
  assert.strictEqual(ev.intentId, intent.intentId, 'the outcome links back to the intent');
  assert.strictEqual(ev.idempotencyKey, 'idem-capture-1');
  assert.strictEqual(ev.fingerprint, 'a'.repeat(64));
  assert.strictEqual(ev.keyEnv, 'test', 'derived from the client key, which is never stored');
  assert.strictEqual(ev.env, 'test', 'the normalized env is derived and stamped end-to-end through the proxy');
  assert.strictEqual(ev.requestBlobSha256, intent.requestBlob, 'the outcome references the intent-time blob');

  // The blob (written at intent time) holds exactly the bytes the stub received.
  const blob = store.readBlob(DATA_DIR, ev.requestBlobSha256);
  assert.strictEqual(blob.toString(), multipart, 'blob holds exactly the bytes the stub received');
  assert.deepStrictEqual(lastCreateBody.toString(), multipart, 'stub received the same bytes');
  // The recorded outcome resolves the intent: nothing left unreconciled.
  assert.ok(!store.unresolvedIntents(DATA_DIR).some((i) => i.intentId === intent.intentId),
    'a successful outcome resolves the intent');

  const serialized = fs.readFileSync(path.join(DATA_DIR, 'audit.log'), 'utf8');
  assert.ok(!serialized.includes('clientkey'), 'the Lob key never reaches the log');
});

test('a stub 422 still produces a letter.create event with status 422', async () => {
  const cookie = await login();
  const r = await request({
    path: '/api/lob/v1/letters', method: 'POST',
    headers: { ...clientKeyHeader, Cookie: cookie, 'Content-Type': 'multipart/form-data; boundary=x' },
  }, 'FORCE_422 body');
  assert.strictEqual(r.status, 422, 'the client sees the real upstream status');
  const ev = readLog().filter((l) => l.type === 'letter.create').pop();
  assert.strictEqual(ev.status, 422);
  assert.strictEqual(ev.letterId, null);
  assert.ok(ev.response.error, 'the 422 body is captured');
});

test('DELETE letter and POST verification are captured', async () => {
  const cookie = await login();
  const del = await request({ path: '/api/lob/v1/letters/ltr_stub123', method: 'DELETE', headers: { ...clientKeyHeader, Cookie: cookie } });
  assert.strictEqual(del.status, 200);
  const store = require('../server.js');
  // A cancel is a mutation, so it too gets a write-ahead intent that the outcome
  // links to and resolves.
  const cancel = readLog().filter((l) => l.type === 'letter.cancel').pop();
  assert.strictEqual(cancel.letterId, 'ltr_stub123');
  assert.strictEqual(cancel.status, 200);
  assert.match(cancel.intentId, store.INTENT_ID_RE, 'the cancel links to its intent');
  const cancelIntent = readLog().find((l) => l.type === 'send.intent' && l.intentId === cancel.intentId);
  assert.ok(cancelIntent, 'the cancel intent was written');
  assert.strictEqual(cancelIntent.lobPath, '/v1/letters/ltr_stub123', 'the intent records the cancel target');
  assert.ok(!store.unresolvedIntents(DATA_DIR).some((i) => i.intentId === cancel.intentId), 'the cancel outcome resolves its intent');

  const addr = { primary_line: '185 Berry St', secondary_line: 'Ste 6100', city: 'San Francisco', state: 'CA', zip_code: '94107' };
  const ver = await request({
    path: '/api/lob/v1/us_verifications', method: 'POST',
    headers: { ...clientKeyHeader, Cookie: cookie, 'Content-Type': 'application/json' },
  }, JSON.stringify(addr));
  assert.strictEqual(ver.status, 200);
  const verify = readLog().filter((l) => l.type === 'address.verify').pop();
  assert.strictEqual(verify.addressSha256,
    store.addressHash({ line1: '185 Berry St', line2: 'Ste 6100', city: 'San Francisco', state: 'CA', zip: '94107' }));
});

test('a plain GET listing through the proxy is NOT captured', async () => {
  const cookie = await login();
  const before = readLog().length;
  await request({ path: '/api/lob/v1/letters?limit=1', method: 'GET', headers: { ...clientKeyHeader, Cookie: cookie } });
  assert.strictEqual(readLog().length, before, 'reads are not audit events');
});

test('GET /api/ledger returns local rows and the unresolved-intents worklist', async () => {
  const store = require('../server.js');
  // Unauthenticated: bounced to login.
  const noauth = await request({ path: '/api/ledger', method: 'GET' });
  assert.strictEqual(noauth.status, 302);
  assert.strictEqual(noauth.headers.location, '/login');

  const cookie = await login();
  // Seed a dangling intent so the worklist is non-empty.
  const dangling = store.writeSendIntent(DATA_DIR, { lobPath: '/v1/letters', reqHeaders: {}, reqBuf: Buffer.from('ledger-dangling') }, Date.now());

  const r = await request({ path: '/api/ledger', method: 'GET', headers: { Cookie: cookie } });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(r.headers['cache-control'], 'no-store', 'the local record carries PII: never cached');
  const data = JSON.parse(r.body);
  assert.ok(Array.isArray(data.rows), 'rows is an array');
  assert.ok(Array.isArray(data.unresolvedIntents), 'unresolvedIntents is a separate array');
  // The earlier successful create in this file shows up as a ledger row.
  assert.ok(data.rows.some((row) => row.type === 'letter.create' && row.letterId === 'ltr_stub123'),
    'a recorded send is a ledger row');
  // The seeded dangling intent is on the worklist.
  assert.ok(data.unresolvedIntents.some((i) => i.intentId === dangling), 'the dangling intent is unresolved');
});

test('POST /api/intents/:id/resolve requires auth, validates, and records the resolution', async () => {
  const store = require('../server.js');
  // Seed a DANGLING intent (no outcome), the exact state the endpoint exists to
  // reconcile: a send whose fate was never recorded.
  const intentId = store.writeSendIntent(DATA_DIR, { lobPath: '/v1/letters', reqHeaders: {}, reqBuf: Buffer.from('dangling-for-endpoint') }, Date.now());
  assert.ok(store.unresolvedIntents(DATA_DIR).some((i) => i.intentId === intentId), 'seeded intent starts unresolved');
  const body = (o) => JSON.stringify(o);

  // Unauthenticated: bounced to login, nothing recorded (auth gate precedes it).
  const noauth = await request({ path: '/api/intents/' + intentId + '/resolve', method: 'POST', headers: { 'Content-Type': 'application/json' } }, body({ resolution: 'not_sent' }));
  assert.strictEqual(noauth.status, 302);
  assert.strictEqual(noauth.headers.location, '/login');

  const cookie = await login();
  // Malformed intent id: 400 before any store access.
  const badId = await request({ path: '/api/intents/not-a-uuid/resolve', method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' } }, body({ resolution: 'not_sent' }));
  assert.strictEqual(badId.status, 400);
  // Bad resolution value: 400.
  const badRes = await request({ path: '/api/intents/' + intentId + '/resolve', method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' } }, body({ resolution: 'bogus' }));
  assert.strictEqual(badRes.status, 400);
  // Well-formed but unknown intent id: 404, no line appended.
  const unknown = await request({ path: '/api/intents/00000000-0000-4000-8000-000000000000/resolve', method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' } }, body({ resolution: 'unknown' }));
  assert.strictEqual(unknown.status, 404);
  // The intent is still unresolved after all the rejected attempts.
  assert.ok(store.unresolvedIntents(DATA_DIR).some((i) => i.intentId === intentId), 'rejected attempts change nothing');

  // Valid: 200, appends send.intent.resolved, clears the worklist.
  const okr = await request({ path: '/api/intents/' + intentId + '/resolve', method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/json' } }, body({ resolution: 'accepted', letterId: 'ltr_reconciled', note: 'confirmed at Lob' }));
  assert.strictEqual(okr.status, 200);
  const resolved = readLog().find((l) => l.type === 'send.intent.resolved' && l.intentId === intentId);
  assert.ok(resolved, 'a send.intent.resolved line was appended');
  assert.strictEqual(resolved.resolution, 'accepted');
  assert.strictEqual(resolved.letterId, 'ltr_reconciled');
  assert.ok(!store.unresolvedIntents(DATA_DIR).some((i) => i.intentId === intentId), 'the intent is now resolved');
});
