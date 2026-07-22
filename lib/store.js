'use strict';
// Persistence: append-only audit log + content-addressed blobs. The durable
// system of record under PD_DATA_DIR:
//   • audit.log  append-only JSONL, one self-contained event per line, written
//                with a SYNCHRONOUS append so the line is on disk before the
//                response that reports it. No line is ever rewritten or deleted.
//   • blobs/     content-addressed raw bytes at blobs/<sha256hex>, written once.
// Every store function takes the data directory explicitly (dependency
// injection), so tests run against a fresh fs.mkdtemp dir. Nothing here runs at
// module load: the directory is created at the entrypoint (ensureDataDir) or
// lazily on first write, so REQUIRING this module creates no directories.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { lobKeyEnv, LOB_KEY_ENV } = require('./config');

// PD_DATA_DIR default lives beside the app root, never inside public/, so it is
// never web-served. __dirname is lib/, so the default resolves to <root>/data
// (one level up). Pure string work: no filesystem touch happens here.
const DATA_DIR = path.resolve(process.env.PD_DATA_DIR || path.join(__dirname, '..', 'data'));
const BLOB_RE = /^[0-9a-f]{64}$/;              // ground rule: blob refs are sha256 hex, nothing else
const LETTER_ID_RE = /^ltr_[A-Za-z0-9]+$/;     // ground rule: Lob letter IDs, before any path/query use
// The chain's genesis `prev`: the first line of a file, having no predecessor,
// points at 64 zeros. Also the head of an empty log.
const CHAIN_GENESIS = '0'.repeat(64);

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// Durable write: open, write ALL bytes, fsync, close. appendFileSync/
// writeFileSync return once the bytes reach the OS page cache, which a crash or
// power loss can drop before the kernel flushes them to the platter. The whole
// point of this store is that a line we told the client is recorded is actually
// on stable storage, so we pay for the fsync. flag selects the semantics ('a'
// append for the log, 'wx' exclusive-create for a content-addressed blob).
// A single fs.writeSync can write FEWER bytes than requested (a large blob is a
// multi-megabyte PDF), unlike fs.writeFileSync which loops internally, so we
// loop until the whole buffer is on the descriptor before fsync. closeSync runs
// in finally so the descriptor is never leaked when a write or the fsync throws.
function writeDurable(filePath, data, flag, mode) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  const fd = fs.openSync(filePath, flag, mode);
  try {
    let written = 0;
    while (written < buf.length) {
      written += fs.writeSync(fd, buf, written, buf.length - written);
    }
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

// Canonical form of a mailing address for correlation hashing: uppercased,
// whitespace-collapsed, ZIP truncated to its 5-digit prefix (so a ZIP+4 on one
// side and a bare 5-digit on the other still correlate). Fed by BOTH the
// us_verifications request (capture) and a letter's recorded recipient
// (export), so a verification can be matched to a letter without parsing the
// multipart letter body.
function normalizeAddressForHash(a) {
  const norm = (s) => String(s == null ? '' : s).toUpperCase().replace(/\s+/g, ' ').trim();
  const zip5 = norm(a && a.zip).replace(/[^0-9].*$/, '').slice(0, 5);
  return [norm(a && a.line1), norm(a && a.line2), norm(a && a.city), norm(a && a.state), zip5].join('|');
}
function addressHash(a) { return sha256Hex(normalizeAddressForHash(a)); }

// Best-effort tighten a directory to 0700. mkdirSync's mode is a no-op on an
// existing directory (the Docker image pre-creates /app/data, and a bind mount
// or restored backup may arrive looser), so the 0700 guarantee is re-applied at
// startup. But chmod requires OWNING the directory: a mounted volume can be
// writable by this process yet owned by another uid, where chmod throws EPERM.
// A previously-working deployment must not crash on upgrade just because it
// cannot re-mode a mount it does not own, so tightening is best-effort. If chmod
// fails AND the directory is actually looser than 0700, warn loudly (it holds
// client PII); a mount already at 0700 or stricter is fine and stays quiet. The
// writability probe below remains the real usability gate.
function tightenDir0700(target) {
  try { fs.chmodSync(target, 0o700); return; }
  catch (e) {
    let mode = null;
    try { mode = fs.statSync(target).mode & 0o777; } catch (_) { /* stat also failed */ }
    if (mode !== null && (mode & 0o077) === 0) return; // already 0700 or stricter
    console.error('WARNING: could not tighten ' + target + ' to 0700 (' + (e.code || e.message) +
      '); current mode ' + (mode === null ? 'unknown' : '0' + mode.toString(8)) +
      '. It holds client PII; ensure it is not group- or other-accessible.');
  }
}

// Create the data directory tree (mode 0700: it holds client PII and mailed
// documents) and prove it is writable. Returns {ok} or {ok:false, error}. Fatal
// at startup, and also called lazily by the writers so tests that never boot
// the entrypoint still work (first-use creation, not module-load).
function ensureDataDir(dir) {
  try {
    const blobs = path.join(dir, 'blobs');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(blobs, { recursive: true, mode: 0o700 });
    // Re-enforce 0700 when we own the tree; best-effort on a mount we do not
    // (tightenDir0700 warns instead of failing the boot). Files created below
    // and by the writers still get 0600 regardless: creating a file needs write
    // permission on the dir, not ownership of it, and the new file is ours.
    tightenDir0700(dir);
    tightenDir0700(blobs);
    // Writability probe: mkdir succeeds on a read-only dir when running as root,
    // so write (then remove) a real file to catch a genuinely unwritable target.
    const probe = path.join(dir, '.pd-write-test');
    fs.writeFileSync(probe, '', { mode: 0o600 });
    fs.unlinkSync(probe);
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'PD_DATA_DIR (' + dir + ') is not usable: ' + (e.code || e.message) };
  }
}

// The chain hashes RAW LINE BYTES, not parsed JSON: a tamperer who rewrites a
// line and re-serializes it to equivalent JSON with different byte spacing must
// still break the chain. Split the file buffer on the newline separator (0x0a)
// and return each non-empty byte slice. A trailing newline leaves an empty
// final slice, correctly ignored; the hash of a line never includes its own
// newline, so the last line (no trailing newline) and every earlier line hash
// on identical rules.
function auditLineSlices(buf) {
  const slices = [];
  let start = 0;
  for (let i = 0; i < buf.length; i += 1) {
    if (buf[i] === 0x0a) {
      if (i > start) slices.push(buf.subarray(start, i));
      start = i + 1;
    }
  }
  if (buf.length > start) slices.push(buf.subarray(start, buf.length));
  return slices;
}

// Scan audit.log from disk and return the current tail: how many lines it holds,
// the hash of the last line's bytes (the chain head, GENESIS for an empty/absent
// log), and the file size we scanned. Size lets auditAppend detect that another
// writer (or a test) changed the file underneath the per-process cache.
function scanAuditTail(dir) {
  let buf;
  try { buf = fs.readFileSync(path.join(dir, 'audit.log')); }
  catch (e) { return { count: 0, hash: CHAIN_GENESIS, size: 0 }; }  // no log yet
  const slices = auditLineSlices(buf);
  const last = slices.length ? slices[slices.length - 1] : null;
  return { count: slices.length, hash: last ? sha256Hex(last) : CHAIN_GENESIS, size: buf.length };
}

// Per-process tail cache keyed by the audit.log path: avoids re-reading the
// whole file on every append. It is a cache, not the source of truth. Before
// trusting it auditAppend compares the on-disk size; a mismatch means something
// changed the file behind our back (concurrent writer, restored backup, a test
// truncating), so we re-scan and log loudly rather than chain onto a stale head.
const auditTails = new Map();

// Append one event as a single JSONL line, hash-chained and fsync'd. Synchronous
// and durable: the line is on stable storage before we answer the request that
// produced it (see writeDurable). Stamps ts (ISO 8601 UTC) from the injected
// clock (Date.now() when omitted). Adds two chain fields:
//   seq   monotonic 1-based line number over the WHOLE file, legacy prefix
//         included, so seq always equals the line's position.
//   prev  lowercase hex sha256 of the PREVIOUS line's raw bytes (its own newline
//         excluded); the first line of the file points at CHAIN_GENESIS.
// Lazily ensures the dir. Fails closed: any throw here (a full disk, an fsync
// error) propagates so the caller refuses the operation rather than reporting a
// record that does not exist.
function auditAppend(dir, event, now) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const p = path.join(dir, 'audit.log');
  // Trust the cached tail only if it still matches the file's size on disk.
  let size = 0;
  try { size = fs.statSync(p).size; } catch (e) { /* no file yet: size 0 */ }
  let tail = auditTails.get(p);
  if (!tail || tail.size !== size) {
    if (tail && tail.size !== size) {
      console.error('AUDIT TAIL CACHE STALE: ' + p + ' is ' + size + ' bytes but the cached tail expected ' +
        tail.size + '. Re-scanning from disk before appending so the chain stays intact.');
    }
    tail = scanAuditTail(dir);
  }
  const seq = tail.count + 1;
  const obj = Object.assign(
    { ts: new Date(now == null ? Date.now() : now).toISOString() }, event, { seq, prev: tail.hash });
  const json = JSON.stringify(obj);
  const lineBytes = Buffer.from(json, 'utf8');
  // mode 0600: audit.log holds client PII. The mode applies only when the file
  // is first created; on an existing file the open reuses its mode (default
  // creation would be 0644 under the usual umask, which we do not want).
  writeDurable(p, json + '\n', 'a', 0o600);
  // Advance the cache: this line is now the tail. size grows by the line bytes
  // plus the one newline separator we appended.
  auditTails.set(p, { count: seq, hash: sha256Hex(lineBytes), size: size + lineBytes.length + 1 });
  return json + '\n';
}

// Walk the whole audit.log and verify the hash chain over raw line bytes.
// Returns { ok, checkedLines, legacyLines, corruptLines, firstBreakSeq, head }:
//   checkedLines   chained lines (seq + prev present) whose prev matched.
//   legacyLines    pre-chain lines with no seq/prev, tolerated: they predate the
//                  chain and cannot carry a back-pointer. They still contribute
//                  their bytes to the running hash, so the first chained line
//                  after them commits to the legacy prefix.
//   corruptLines   lines that do not parse as JSON at all.
//   firstBreakSeq  seq of the first chained line whose prev did not match, or
//                  null if the chain is intact.
//   head           hash of the last line's bytes: an external commitment. Anchor
//                  it (a timestamp, a countersignature) and any later rewrite of
//                  history is detectable.
// ok is false if any chained line's prev mismatches. A corrupt (unparseable)
// line does not by itself set ok=false (auditReadStats already reports and warns
// on corruption); but its bytes still advance the running hash, so a chained
// line after it is validated against reality.
function auditVerifyChain(dir) {
  let buf;
  try { buf = fs.readFileSync(path.join(dir, 'audit.log')); }
  catch (e) { return { ok: true, checkedLines: 0, legacyLines: 0, corruptLines: 0, firstBreakSeq: null, head: CHAIN_GENESIS }; }
  const slices = auditLineSlices(buf);
  let ok = true;
  let checkedLines = 0;
  let legacyLines = 0;
  let corruptLines = 0;
  let firstBreakSeq = null;
  let prevHash = CHAIN_GENESIS;
  for (const slice of slices) {
    const thisHash = sha256Hex(slice);
    let ev = null;
    try { ev = JSON.parse(slice.toString('utf8')); }
    catch (e) { corruptLines += 1; prevHash = thisHash; continue; }
    if (typeof ev.seq === 'number' && typeof ev.prev === 'string') {
      if (ev.prev !== prevHash) {
        ok = false;
        if (firstBreakSeq === null) firstBreakSeq = ev.seq;
      } else {
        checkedLines += 1;
      }
    } else {
      legacyLines += 1;  // pre-chain line: no back-pointer to verify
    }
    prevHash = thisHash;
  }
  const head = slices.length ? sha256Hex(slices[slices.length - 1]) : CHAIN_GENESIS;
  if (!ok) {
    console.error('AUDIT CHAIN BROKEN: ' + path.join(dir, 'audit.log') +
      ' first break at seq ' + firstBreakSeq + '. A line was altered, inserted, or removed.');
  }
  return { ok, checkedLines, legacyLines, corruptLines, firstBreakSeq, head };
}

// Content-addressed write: bytes land at blobs/<sha256hex>, written once with
// the wx flag so identical content dedupes and an existing blob is never
// rewritten. Returns the hash.
function blobStore(dir, buf) {
  const hex = sha256Hex(buf);
  const blobsDir = path.join(dir, 'blobs');
  fs.mkdirSync(blobsDir, { recursive: true, mode: 0o700 });
  // mode 0600: blobs are the exact request bytes and rendered PDFs (client PII).
  // Durable, same reasoning as the log: a blob the log line points at must be on
  // stable storage before that line is. wx makes the create exclusive, so
  // identical content dedupes and an existing blob is never rewritten.
  try { writeDurable(path.join(blobsDir, hex), buf, 'wx', 0o600); }
  catch (e) { if (e.code !== 'EEXIST') throw e; }  // identical content already stored: fine
  return hex;
}

// Resolve a blob path, refusing any hash that is not exactly 64 hex chars
// (ground rule: no client-influenced value becomes a filesystem path without
// strict format validation). Returns null on a bad ref.
function blobPath(dir, hex) {
  if (!BLOB_RE.test(String(hex == null ? '' : hex))) return null;
  return path.join(dir, 'blobs', hex);
}
function readBlob(dir, hex) {
  const p = blobPath(dir, hex);
  if (!p) return null;
  try { return fs.readFileSync(p); } catch (e) { return null; }
}

// Read audit.log into { lines, corruptCount }. A line that does not parse as
// JSON is SKIPPED wherever it occurs, not only a truncated final line: the log
// is append-only and written with a synchronous append, so an unparseable line
// in the middle is real data loss from the evidentiary record, not a benign
// crash-tail. corruptCount reports how many were dropped so a caller (a proof
// export) can record it, and a loud console.error fires on any corruption so the
// operator learns of it at read time, not only when an export surfaces it.
function auditReadStats(dir) {
  let raw;
  try { raw = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8'); }
  catch (e) { return { lines: [], corruptCount: 0 }; }  // no log yet
  const lines = [];
  let corruptCount = 0;
  for (const line of raw.split('\n')) {
    if (!line) continue;
    try { lines.push(JSON.parse(line)); }
    catch (e) { corruptCount += 1; }
  }
  if (corruptCount > 0) {
    console.error('AUDIT LOG CORRUPTION: ' + corruptCount + ' unparseable line(s) in ' +
      path.join(dir, 'audit.log') + '. Those events are lost from the readable record.');
  }
  return { lines, corruptCount };
}

// Parsed events only, for callers that do not need the corrupt count (the
// duplicate-send query and the like). Delegates to auditReadStats.
function auditReadLines(dir) { return auditReadStats(dir).lines; }

// Pure filter over parsed events. Linear scan is the right simplicity at
// solo-operator volume; no index is wanted.
function auditQuery(lines, predicate) { return lines.filter(predicate); }

// Prior SUCCESSFUL letter creations for a given client fingerprint, newest
// concerns last (audit order is chronological). Powers the duplicate warning:
// the durable server record outlives the client's 24h localStorage window, so
// a resend months later is still flagged. Returns only what the UI needs, never
// key material.
function findSendsByFingerprint(lines, fingerprint) {
  return auditQuery(lines, (l) =>
    l.type === 'letter.create' && l.fingerprint === fingerprint &&
    typeof l.status === 'number' && l.status >= 200 && l.status < 300 && l.letterId
  ).map((l) => ({ date: l.ts, letterId: l.letterId, keyEnv: l.keyEnv || null }));
}

// Which upstream calls the proxy captures, keyed by (method, path). Returns the
// audit event type or null. Only these three are legally consequential.
function proxyAuditType(method, lobPath) {
  const p = String(lobPath == null ? '' : lobPath).split('?')[0];
  if (method === 'POST' && p === '/v1/letters') return 'letter.create';
  if (method === 'DELETE' && /^\/v1\/letters\/ltr_[A-Za-z0-9]+$/.test(p)) return 'letter.cancel';
  if (method === 'POST' && p === '/v1/us_verifications') return 'address.verify';
  return null;
}

// The key the proxy actually sent upstream lives in a Basic auth header as
// base64("<key>:"). Decode just enough to classify test/live, then discard: the
// key itself is never returned, logged, or stored. A missing client header
// means the server key (PD_LOB_KEY) was injected, so fall back to classifying
// that.
function classifyProxyKeyEnv(authHeader) {
  if (!authHeader) return LOB_KEY_ENV;
  const m = /^Basic\s+(.+)$/i.exec(String(authHeader));
  if (!m) return null;
  try { return lobKeyEnv(Buffer.from(m[1], 'base64').toString('utf8').split(':')[0]); }
  catch (e) { return null; }
}

function firstHeader(h) { return (h == null) ? null : String(Array.isArray(h) ? h[0] : h); }

// Build and persist the audit event for a captured proxy call. Writes the blob
// (letter.create only) BEFORE the log line, so a referenced blob always exists
// by the time the line naming it is on disk. Never stores Authorization
// material: only the derived test/live classification.
function captureProxyEvent(dir, type, lobPath, reqHeaders, upstreamAuth, reqBuf, status, respBuf) {
  const keyEnv = classifyProxyKeyEnv(upstreamAuth);
  let response;
  try { response = JSON.parse(respBuf.toString('utf8')); }
  catch (e) { response = { _unparsed: respBuf.toString('utf8').slice(0, 4000) }; }
  if (type === 'letter.create') {
    const requestBlobSha256 = blobStore(dir, reqBuf);
    auditAppend(dir, {
      type,
      status,
      letterId: (response && typeof response.id === 'string' && LETTER_ID_RE.test(response.id)) ? response.id : null,
      requestBlobSha256,
      requestBytes: reqBuf.length,
      idempotencyKey: firstHeader(reqHeaders['idempotency-key']),
      fingerprint: firstHeader(reqHeaders['x-pd-fingerprint']),
      // Hash of the TYPED recipient address (client mirror of
      // normalizeAddressForHash). Correlating a verification to a letter by this
      // is immune to Lob reformatting the recipient in its response, which the
      // response-derived hash is not; the export prefers this and falls back.
      recipientSha256: firstHeader(reqHeaders['x-pd-recipient-hash']),
      keyEnv,
      response,
    });
  } else if (type === 'letter.cancel') {
    const m = /\/v1\/letters\/(ltr_[A-Za-z0-9]+)/.exec(String(lobPath == null ? '' : lobPath).split('?')[0]);
    auditAppend(dir, { type, status, letterId: m ? m[1] : null, keyEnv, response });
  } else if (type === 'address.verify') {
    let addr = null;
    try {
      const b = JSON.parse(reqBuf.toString('utf8'));
      addr = { line1: b.primary_line, line2: b.secondary_line, city: b.city, state: b.state, zip: b.zip_code };
    } catch (e) { /* unparseable request body: leave addr null */ }
    auditAppend(dir, { type, status, addressSha256: addr ? addressHash(addr) : null, keyEnv, response });
  }
}

module.exports = {
  DATA_DIR, BLOB_RE, LETTER_ID_RE,
  sha256Hex, writeDurable, normalizeAddressForHash, addressHash,
  ensureDataDir, auditAppend, auditVerifyChain, blobStore, blobPath, readBlob,
  auditReadLines, auditReadStats, auditQuery, findSendsByFingerprint,
  proxyAuditType, classifyProxyKeyEnv, firstHeader, captureProxyEvent,
};
