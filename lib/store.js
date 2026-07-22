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

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
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

// Append one event as a single JSONL line. Synchronous: the line must be on
// disk before we answer the request that produced it. Stamps ts (ISO 8601 UTC)
// from the injected clock (Date.now() when omitted). Lazily ensures the dir.
function auditAppend(dir, event, now) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const line = JSON.stringify(Object.assign(
    { ts: new Date(now == null ? Date.now() : now).toISOString() }, event)) + '\n';
  // mode 0600: audit.log holds client PII. The mode applies when the file is
  // first created; appendFileSync ignores it on an existing file (default
  // creation would be 0644 under the usual umask, which we do not want).
  fs.appendFileSync(path.join(dir, 'audit.log'), line, { mode: 0o600 });
  return line;
}

// Content-addressed write: bytes land at blobs/<sha256hex>, written once with
// the wx flag so identical content dedupes and an existing blob is never
// rewritten. Returns the hash.
function blobStore(dir, buf) {
  const hex = sha256Hex(buf);
  const blobsDir = path.join(dir, 'blobs');
  fs.mkdirSync(blobsDir, { recursive: true, mode: 0o700 });
  // mode 0600: blobs are the exact request bytes and rendered PDFs (client PII).
  try { fs.writeFileSync(path.join(blobsDir, hex), buf, { flag: 'wx', mode: 0o600 }); }
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
  sha256Hex, normalizeAddressForHash, addressHash,
  ensureDataDir, auditAppend, blobStore, blobPath, readBlob,
  auditReadLines, auditReadStats, auditQuery, findSendsByFingerprint,
  proxyAuditType, classifyProxyKeyEnv, firstHeader, captureProxyEvent,
};
