'use strict';
// Fix for review finding #1: the proof export correlates a verification to a
// letter by the hash of the TYPED recipient address (sent as X-PD-Recipient-Hash),
// which is immune to Lob reformatting the recipient in its response. Two things
// must hold: (a) the client's normalizeAddressForHash matches the server's
// byte-for-byte (or the client hash never matches a server-computed verify
// hash), and (b) buildProofPackage correlates via that hash even when the
// response `to` normalizes differently.
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');

const DATA_DIR_SENTINEL = path.join(os.tmpdir(), 'pd-rhash-noexist-' + process.pid);
process.env.PD_DATA_DIR = DATA_DIR_SENTINEL;
process.env.PD_SECRET = process.env.PD_SECRET || 'rhash-secret-fixed-0123456789abcdef';

const test = require('node:test');
const assert = require('node:assert');
const store = require('../server.js');

// Import the client normalizeAddressForHash from the shipped ES module
// (js/address.mjs) and compare it, byte-for-byte, against the server's.
const { normalizeAddressForHash: clientNormalize } = require('../public/js/address.mjs');

// Minimal store-only ZIP entry extractor (independent of server.js's writer):
// scan the central directory for `name`, then read its stored bytes.
function unzipEntry(buf, name) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0; i--) { if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; } }
  assert.notStrictEqual(eocd, -1, 'EOCD found');
  const total = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 14);
  for (let n = 0; n < total; n++) {
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOff = buf.readUInt32LE(p + 42);
    const entryName = buf.slice(p + 46, p + 46 + nameLen).toString('utf8');
    if (entryName === name) {
      const lNameLen = buf.readUInt16LE(localOff + 26);
      const lExtraLen = buf.readUInt16LE(localOff + 28);
      const dataStart = localOff + 30 + lNameLen + lExtraLen;
      return buf.slice(dataStart, dataStart + compSize);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  return null;
}

test('client and server normalizeAddressForHash agree byte-for-byte', () => {
  const cases = [
    { line1: '185 Berry Street', line2: 'Ste 6100', city: 'San Francisco', state: 'CA', zip: '94107-1234' },
    { line1: '  123   main st  ', line2: '', city: 'nowhere', state: 'zz', zip: '00000' },
    { line1: '1 A St', line2: null, city: 'X', state: 'NY', zip: '10001' },
    { line1: '', line2: '', city: '', state: '', zip: '' },
  ];
  for (const a of cases) {
    assert.strictEqual(clientNormalize(a), store.normalizeAddressForHash(a),
      'normalized strings must match for ' + JSON.stringify(a));
    // And therefore the digests match: the client hashes utf8 bytes of this
    // string via SHA-256, exactly what server.addressHash does.
    const crypto = require('node:crypto');
    const clientHash = crypto.createHash('sha256').update(Buffer.from(clientNormalize(a), 'utf8')).digest('hex');
    assert.strictEqual(clientHash, store.addressHash(a), 'digests match for ' + JSON.stringify(a));
  }
});

test('buildProofPackage correlates a verification via the typed-address hash even when the response `to` differs', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-rhash-'));
  // The operator typed "185 Berry Street"; the verification ran on that typed
  // address (server hashes it), and the client sent the same typed hash on
  // create. Lob's letter response echoes an ABBREVIATED "185 BERRY ST", whose
  // normalized hash differs, so the old response-only correlation would miss.
  const typed = { line1: '185 Berry Street', line2: '', city: 'San Francisco', state: 'CA', zip: '94107' };
  const typedHash = store.addressHash(typed);
  const responseToHash = store.addressHash({ line1: '185 BERRY ST', line2: '', city: 'SAN FRANCISCO', state: 'CA', zip: '94107' });
  assert.notStrictEqual(typedHash, responseToHash, 'the reformatted response address hashes differently');

  store.blobStore(dir, Buffer.from('multipart bytes'));
  store.auditAppend(dir, {
    type: 'letter.create', status: 200, letterId: 'ltr_rh1',
    requestBlobSha256: store.sha256Hex(Buffer.from('multipart bytes')), requestBytes: 15,
    recipientSha256: typedHash, keyEnv: 'live',
    response: { id: 'ltr_rh1', to: { address_line1: '185 BERRY ST', address_line2: '', address_city: 'SAN FRANCISCO', address_state: 'CA', address_zip: '94107' } },
  });
  // The verification was on the typed address, so its stored hash is typedHash.
  store.auditAppend(dir, { type: 'address.verify', status: 200, addressSha256: typedHash, keyEnv: 'live', response: { deliverability: 'deliverable' } });

  const pkg = await store.buildProofPackage(dir, 'ltr_rh1', {
    now: () => Date.parse('2026-07-18T00:00:00Z'),
    fetchLetter: async () => ({ ok: true, letter: { id: 'ltr_rh1', url: 'https://lob-assets.com/ltr_rh1.pdf' } }),
    fetchAsset: async () => ({ ok: true, bytes: Buffer.from('%PDF') }),
  });
  const verifs = JSON.parse(unzipEntry(pkg.zip, 'verifications.json').toString('utf8'));
  assert.strictEqual(verifs.length, 1, 'the verification is correlated via the typed-address hash');
  assert.strictEqual(verifs[0].type, 'address.verify');
});

test('correlation still falls back to the response `to` hash when no recipientSha256 was recorded', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-rhash-'));
  // Older record with no X-PD-Recipient-Hash header: the response `to` matches
  // the verified address, so the fallback path still correlates.
  const addr = { line1: '1 MAIN ST', line2: '', city: 'ANYTOWN', state: 'NY', zip: '10001' };
  const h = store.addressHash(addr);
  store.auditAppend(dir, {
    type: 'letter.create', status: 200, letterId: 'ltr_rh2', keyEnv: 'live',
    response: { id: 'ltr_rh2', to: { address_line1: '1 Main St', address_line2: '', address_city: 'Anytown', address_state: 'NY', address_zip: '10001' } },
  });
  store.auditAppend(dir, { type: 'address.verify', status: 200, addressSha256: h, keyEnv: 'live', response: { deliverability: 'deliverable' } });
  const pkg = await store.buildProofPackage(dir, 'ltr_rh2', {
    now: () => Date.parse('2026-07-18T00:00:00Z'),
    fetchLetter: async () => ({ ok: false, status: 404 }),
    fetchAsset: async () => ({ ok: false, status: 404 }),
  });
  const verifs = JSON.parse(unzipEntry(pkg.zip, 'verifications.json').toString('utf8'));
  assert.strictEqual(verifs.length, 1, 'fallback correlation via the response address still works');
});
