'use strict';
// Proof package export: a downloadable, self-contained evidence bundle per
// letter (the exact bytes sent to Lob, Lob's creation response, the rendered
// PDF, live tracking, correlated address verifications, and every audit line
// referencing the letter). Delivered as a store-only ZIP so the payload (mostly
// already-compressed PDF) is archived verbatim with a tiny, auditable writer.
// The writer is validated by an INDEPENDENT reader in the test suite, never
// only by itself.
const { PROXY_TIMEOUT_MS } = require('./config');
const {
  sha256Hex, addressHash, blobStore, readBlob, auditReadStats, auditAppend,
} = require('./store');

// CRC-32 (IEEE, the ZIP polynomial). Table built once at load: pure arithmetic,
// no filesystem touch.
const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC32_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// Store-only (method 0, no compression) ZIP from [{name, data:Buffer}].
// Deterministic: a fixed 1980-01-01 DOS timestamp, so identical inputs produce
// identical bytes (testable). Entry names here are ASCII, so no UTF-8 flag.
function zipStore(entries) {
  const DOS_TIME = 0, DOS_DATE = 0x21; // 1980-01-01 00:00:00
  const locals = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, 'utf8');
    const data = e.data;
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); // local file header signature
    local.writeUInt16LE(20, 4);         // version needed to extract (2.0)
    local.writeUInt16LE(0, 6);          // general purpose bit flag
    local.writeUInt16LE(0, 8);          // compression method: store
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed size == uncompressed
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);           // extra field length
    locals.push(local, nameBuf, data);
    const localOffset = offset;
    offset += local.length + nameBuf.length + data.length;

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);  // central directory header signature
    cd.writeUInt16LE(20, 4);          // version made by
    cd.writeUInt16LE(20, 6);          // version needed
    cd.writeUInt16LE(0, 8);           // gp flag
    cd.writeUInt16LE(0, 10);          // method
    cd.writeUInt16LE(DOS_TIME, 12);
    cd.writeUInt16LE(DOS_DATE, 14);
    cd.writeUInt32LE(crc, 16);
    cd.writeUInt32LE(data.length, 20);
    cd.writeUInt32LE(data.length, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);          // extra len
    cd.writeUInt16LE(0, 32);          // comment len
    cd.writeUInt16LE(0, 34);          // disk number start
    cd.writeUInt16LE(0, 36);          // internal attrs
    cd.writeUInt32LE(0, 38);          // external attrs
    cd.writeUInt32LE(localOffset, 42);
    central.push(cd, nameBuf);
  }
  const cdBuf = Buffer.concat(central);
  const cdOffset = offset;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);   // end of central directory signature
  eocd.writeUInt16LE(0, 4);            // disk number
  eocd.writeUInt16LE(0, 6);            // disk with central directory
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(cdOffset, 14);
  eocd.writeUInt16LE(0, 18);           // comment length
  return Buffer.concat([...locals, cdBuf, eocd]);
}

// Per-fetch size cap for export-time upstream reads. Generous headroom over the
// 52 MB proxy body limit (a rendered letter derives from an upload no larger
// than that), while still bounding a runaway or malformed asset so a single
// export cannot exhaust memory on the single-process server.
const PROOF_FETCH_MAX_BYTES = 60 * 1024 * 1024;

// Buffered GET against an explicit target (single configured origin, never
// client-derived), capped at maxBytes (default PROOF_FETCH_MAX_BYTES). Resolves
// (never rejects) so a fetch failure, timeout, or oversize is data (recorded as
// a manifest miss), not a thrown error that could sink an export.
function httpGetBuffer(target, maxBytes) {
  const cap = (typeof maxBytes === 'number' && maxBytes > 0) ? maxBytes : PROOF_FETCH_MAX_BYTES;
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const req = target.transport.request({
      hostname: target.hostname, port: target.port, path: target.path, method: 'GET',
      headers: target.headers || {},
    }, (r) => {
      const parts = [];
      let total = 0;
      r.on('data', (c) => {
        total += c.length;
        if (total > cap) {
          r.destroy();
          return done({ status: 0, buffer: Buffer.alloc(0), error: 'response exceeded ' + cap + ' bytes' });
        }
        parts.push(c);
      });
      r.on('end', () => done({ status: r.statusCode, buffer: Buffer.concat(parts), headers: r.headers }));
      r.on('error', (e) => done({ status: 0, buffer: Buffer.alloc(0), error: e.code || e.message }));
    });
    req.on('error', (e) => done({ status: 0, buffer: Buffer.alloc(0), error: e.code || e.message }));
    req.setTimeout(PROXY_TIMEOUT_MS, () => req.destroy(new Error('Upstream request timed out')));
    req.end();
  });
}

// Assemble the per-letter evidence bundle as a store-only ZIP. Network-pure:
// all upstream access is via injected fetchers (deps.fetchLetter/fetchAsset),
// so tests build a full package with no sockets. A fetch failure never sinks
// the export: the package is built from stored data and the manifest records
// exactly what could not be fetched and why. Writes the fetched rendered PDF as
// a content-addressed blob and appends a proof.export audit event.
async function buildProofPackage(dir, letterId, deps) {
  deps = deps || {};
  const now = deps.now ? deps.now() : Date.now();
  const generatedAt = new Date(now).toISOString();
  // auditCorruptLines: how many audit lines could not be parsed on this read. A
  // proof is an evidentiary record, so silent mid-log data loss is reported in
  // the bundle, not hidden. The reader also logs it loudly server-side.
  const { lines, corruptCount: auditCorruptLines } = auditReadStats(dir);
  const referencing = lines.filter((l) =>
    l.letterId === letterId || (l.response && l.response.id === letterId));
  const create = referencing.filter((l) => l.type === 'letter.create').pop() || null;

  const entries = [];
  const inventory = [];
  const fetched = [];
  const missing = [];
  const addFile = (name, data) => {
    entries.push({ name, data });
    inventory.push({ name, sha256: sha256Hex(data), bytes: data.length });
  };

  // request-body.bin: the exact bytes sent upstream, from the content-addressed blob.
  if (create && create.requestBlobSha256) {
    const blob = readBlob(dir, create.requestBlobSha256);
    if (blob) addFile('request-body.bin', blob);
    else missing.push({ name: 'request-body.bin', reason: 'stored blob ' + create.requestBlobSha256 + ' not found' });
  } else {
    missing.push({ name: 'request-body.bin', reason: 'no letter.create record for this letter' });
  }

  // creation-response.json: Lob's response as captured.
  if (create && create.response) addFile('creation-response.json', Buffer.from(JSON.stringify(create.response, null, 2)));
  else missing.push({ name: 'creation-response.json', reason: 'no letter.create record for this letter' });

  // tracking.json: the letter object + tracking events, fetched live at export time.
  let letterObj = null;
  try {
    const lr = deps.fetchLetter ? await deps.fetchLetter(letterId) : { ok: false, error: 'no letter fetcher' };
    if (lr && lr.ok) {
      letterObj = lr.letter;
      addFile('tracking.json', Buffer.from(JSON.stringify(letterObj, null, 2)));
      fetched.push('tracking.json');
    } else {
      missing.push({ name: 'tracking.json', reason: (lr && (lr.error || ('HTTP ' + lr.status))) || 'letter fetch failed' });
    }
  } catch (e) {
    missing.push({ name: 'tracking.json', reason: 'letter fetch error: ' + (e && (e.code || e.message)) });
  }

  // rendered.pdf: what was physically printed and mailed, fetched at export time.
  const pdfUrl = letterObj && typeof letterObj.url === 'string' ? letterObj.url : null;
  if (pdfUrl) {
    try {
      const ar = deps.fetchAsset ? await deps.fetchAsset(pdfUrl) : { ok: false, error: 'no asset fetcher' };
      if (ar && ar.ok && ar.bytes && ar.bytes.length) {
        blobStore(dir, ar.bytes); // archive a copy content-addressed
        addFile('rendered.pdf', ar.bytes);
        fetched.push('rendered.pdf');
      } else {
        missing.push({ name: 'rendered.pdf', reason: (ar && (ar.error || ('HTTP ' + ar.status))) || 'rendered PDF fetch failed' });
      }
    } catch (e) {
      missing.push({ name: 'rendered.pdf', reason: 'rendered PDF fetch error: ' + (e && (e.code || e.message)) });
    }
  } else {
    missing.push({ name: 'rendered.pdf', reason: 'no rendered PDF URL (letter object unavailable)' });
  }

  // verifications.json: stored address.verify events whose address matches the
  // recorded recipient, correlated by hash (no multipart parsing). Two hashes
  // are accepted so a verification is not silently dropped: the client-sent hash
  // of the TYPED recipient (recipientSha256, which matches the typed address the
  // verification also ran on) and, as a fallback for older records or a missing
  // header, the hash derived from Lob's echoed response `to`. Always included,
  // possibly empty.
  const to = create && create.response && create.response.to;
  const recipientHashes = new Set();
  if (create && create.recipientSha256) recipientHashes.add(create.recipientSha256);
  if (to && typeof to === 'object') {
    recipientHashes.add(addressHash({ line1: to.address_line1, line2: to.address_line2, city: to.address_city, state: to.address_state, zip: to.address_zip }));
  }
  const verifications = lines.filter((l) => l.type === 'address.verify' && l.addressSha256 && recipientHashes.has(l.addressSha256));
  addFile('verifications.json', Buffer.from(JSON.stringify(verifications, null, 2)));

  // audit.jsonl: every stored line referencing this letter id.
  addFile('audit.jsonl', Buffer.from(referencing.map((l) => JSON.stringify(l)).join('\n') + (referencing.length ? '\n' : '')));

  // manifest.json: built last because it inventories every OTHER file.
  const recipient = (to && typeof to === 'object') ? {
    name: to.name || '', company: to.company || '',
    line1: to.address_line1 || '', line2: to.address_line2 || '',
    city: to.address_city || '', state: to.address_state || '', zip: to.address_zip || '',
  } : null;
  const src = (create && create.response) ? create.response : {};
  const options = {
    mail_type: src.mail_type != null ? src.mail_type : null,
    color: src.color != null ? src.color : null,
    double_sided: src.double_sided != null ? src.double_sided : null,
    extra_service: src.extra_service != null ? src.extra_service : null,
    use_type: src.use_type != null ? src.use_type : null,
    address_placement: src.address_placement != null ? src.address_placement : null,
    perforated_page: src.perforated_page != null ? src.perforated_page : null,
    return_envelope: src.return_envelope != null ? src.return_envelope : null,
    send_date: src.send_date != null ? src.send_date : null,
    expected_delivery_date: src.expected_delivery_date != null ? src.expected_delivery_date : null,
  };
  const manifest = {
    letterId,
    generatedAt,
    // Top-level completeness signals so a partial bundle is never mistaken for a
    // full evidentiary record. hasLocalRecord is false when this letter was not
    // sent through this app (no letter.create capture), which is the serious
    // case: the exact request bytes and Lob's creation response are absent.
    // complete is true only when nothing at all is missing.
    complete: missing.length === 0,
    hasLocalRecord: !!create,
    keyEnv: create ? (create.keyEnv || null) : null,
    idempotencyKey: create ? (create.idempotencyKey || null) : null,
    fingerprint: create ? (create.fingerprint || null) : null,
    recipient,
    options,
    files: inventory,
    fetched,
    missing,
    // Count of audit lines that failed to parse when this bundle was built. A
    // nonzero value means some events are unreadable, so the audit.jsonl and the
    // derived fields may be incomplete for reasons unrelated to a fetch miss.
    auditCorruptLines,
    note: 'USPS does not confirm final delivery for ordinary First-Class mail. This package is the operator record of what was submitted to Lob and rendered for mailing.',
  };
  entries.push({ name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest, null, 2)) });

  const zip = zipStore(entries);
  const packageSha256 = sha256Hex(zip);
  const exportEvent = { type: 'proof.export', letterId, packageSha256, complete: missing.length === 0, hasLocalRecord: !!create, fetched, missing: missing.map((m) => m.name), auditCorruptLines };
  auditAppend(dir, exportEvent, now);
  return { zip, manifest, packageSha256, missing, exportEvent };
}

module.exports = {
  crc32, zipStore, PROOF_FETCH_MAX_BYTES, httpGetBuffer, buildProofPackage,
};
