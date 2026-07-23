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
// Intent IDs are crypto.randomUUID() (lowercase v4). Validated before an id from
// the URL is used to look one up (ground rule: no client value without a format
// check first).
const INTENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// The chain's genesis `prev`: the first line of a file, having no predecessor,
// points at 64 zeros. Also the head of an empty log.
const CHAIN_GENESIS = '0'.repeat(64);
// The three ways an operator can reconcile an unresolved write-ahead intent.
const INTENT_RESOLUTIONS = new Set(['accepted', 'not_sent', 'unknown']);

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

// fsync a DIRECTORY so a child file's newly-created directory entry is durable.
// fsync(file_fd) flushes the file's own data and inode, but the entry that makes
// a NEW filename resolvable is a change to the parent directory, made durable
// only by fsync'ing the directory itself. Open read-only (a directory cannot be
// opened writable). Some platforms/filesystems reject fsync on a directory fd
// (EINVAL) or the open (EISDIR/EACCES); the child file's own fsync has already
// run, so treat a directory-fsync failure as best-effort rather than failing a
// write that otherwise succeeded.
function fsyncDir(dir) {
  let dfd;
  try { dfd = fs.openSync(dir, 'r'); }
  catch (e) { return; }
  try { fs.fsyncSync(dfd); }
  catch (e) { /* directory fsync unsupported here; the file fsync stands */ }
  finally { fs.closeSync(dfd); }
}

// Durable write: open, write ALL bytes, fsync the file, close, and fsync the
// parent directory when the file was newly created. appendFileSync/
// writeFileSync return once the bytes reach the OS page cache, which a crash or
// power loss can drop before the kernel flushes them to the platter. The whole
// point of this store is that a line we told the client is recorded is actually
// on stable storage, so we pay for the fsync. flag selects the semantics ('a'
// append for the log, 'wx' exclusive-create for a content-addressed blob, 'w'
// create/truncate for an export ZIP).
// A single fs.writeSync can write FEWER bytes than requested (a large blob is a
// multi-megabyte PDF), unlike fs.writeFileSync which loops internally, so we
// loop until the whole buffer is on the descriptor before fsync. closeSync runs
// in finally so the descriptor is never leaked when a write or the fsync throws.
// When we CREATE a file (a new blob, the first audit.log line, an export ZIP),
// the file's fsync alone does not make its name durable, so we also fsync the
// containing directory; a plain append to an existing file adds no directory
// entry, so that (hot) path skips the extra fsync.
function writeDurable(filePath, data, flag, mode) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
  // Newly created iff the name did not exist just before the open. ('wx' also
  // implies new; existsSync being false covers it. A race that creates the file
  // between this check and the open only makes us fsync the directory when we did
  // not strictly need to, which is harmless.)
  const isNew = !fs.existsSync(filePath);
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
  if (isNew) fsyncDir(path.dirname(filePath));
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
    // exports/ holds the persisted proof-package ZIPs (the mailed documents and
    // Lob's responses), so it is created 0700 alongside the rest of the tree.
    const exports = path.join(dir, 'exports');
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(blobs, { recursive: true, mode: 0o700 });
    fs.mkdirSync(exports, { recursive: true, mode: 0o700 });
    // Re-enforce 0700 when we own the tree; best-effort on a mount we do not
    // (tightenDir0700 warns instead of failing the boot). Files created below
    // and by the writers still get 0600 regardless: creating a file needs write
    // permission on the dir, not ownership of it, and the new file is ours.
    tightenDir0700(dir);
    tightenDir0700(blobs);
    tightenDir0700(exports);
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

// Cross-process append lock. The app is single-process by design, so within one
// process all store writes are synchronous and never interleave; this lock is
// the defense for the ONE case the tail cache cannot cover: a SECOND writer on
// the same PD_DATA_DIR (an accidental double start, or a restore/cron job that
// appends). Without serialization two processes can read the same tail size,
// both compute seq=N+1, and the second line's prev then cannot match its true
// predecessor, so auditVerifyChain reports the record as tampered even though
// nothing was rewritten. An advisory lockfile (atomic O_EXCL create) serializes
// the read-decide-write section across processes. In normal single-process
// operation the lock is always free, so it costs only a create + unlink per
// append and never waits.
const LOCK_STALE_MS = 5000;    // a real append finishes in single-digit ms; a lock older than this means a crashed holder
const LOCK_TIMEOUT_MS = 12000; // give up (and fail closed) rather than wait forever on a wedged writer
const LOCK_RETRY_MS = 25;      // backoff between acquire attempts under contention

// Synchronous sleep with no busy-spin and no dependency: wait on an atomic that
// never changes, so the wait always times out after ms. Only reached under lock
// contention (a second writer, or a stale lock after a crash), never on the
// normal single-process path.
const SLEEP_BUF = new Int32Array(new SharedArrayBuffer(4));
function syncSleep(ms) { Atomics.wait(SLEEP_BUF, 0, 0, ms); }

// Acquire the append lock for dir, returning a handle to release. Steals a lock
// older than LOCK_STALE_MS (its holder crashed mid-append, so a stale lock must
// self-heal rather than wedge every future append). Throws on timeout so the
// caller fails closed, consistent with the rest of the write path.
function acquireAppendLock(dir) {
  const lockPath = path.join(dir, 'audit.log.lock');
  const start = Date.now();
  for (;;) {
    try {
      const fd = fs.openSync(lockPath, 'wx', 0o600); // atomic exclusive create == acquire
      try { fs.writeSync(fd, String(process.pid)); } catch (e) { /* pid is only for debugging */ }
      return { fd, lockPath };
    } catch (e) {
      if (e.code !== 'EEXIST') throw e; // a real error (e.g. unwritable dir), not contention
      let mtimeMs = 0;
      try { mtimeMs = fs.statSync(lockPath).mtimeMs; }
      catch (e2) { continue; } // the lock vanished between open and stat: retry the create
      if (Date.now() - mtimeMs > LOCK_STALE_MS) {
        try { fs.unlinkSync(lockPath); } catch (e2) { /* another process already stole it */ }
        continue;
      }
      if (Date.now() - start > LOCK_TIMEOUT_MS) {
        throw new Error('Timed out acquiring the audit append lock (' + lockPath + '); another writer may be holding it.');
      }
      syncSleep(LOCK_RETRY_MS);
    }
  }
}

function releaseAppendLock(lock) {
  if (!lock) return;
  try { fs.closeSync(lock.fd); } catch (e) { /* already closed */ }
  try { fs.unlinkSync(lock.lockPath); } catch (e) { /* already removed or stolen */ }
}

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
  // Hold the cross-process lock across the whole read-decide-write section, so a
  // second writer cannot slip an append between our size read and our write and
  // desync the chain. The size-mismatch re-scan below still runs INSIDE the lock,
  // so another process's appends since our last write are picked up correctly.
  const lock = acquireAppendLock(dir);
  try {
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
  } finally {
    releaseAppendLock(lock);
  }
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
function captureProxyEvent(dir, type, lobPath, reqHeaders, upstreamAuth, reqBuf, status, respBuf, intentId) {
  const keyEnv = classifyProxyKeyEnv(upstreamAuth);
  // env is the normalized environment of the upstream key ('test'/'live'), never
  // null: an unclassifiable key becomes 'envUnknown'. keyEnv (nullable) is kept
  // for existing readers (the fingerprint list, the manifest, the ledger); env
  // is the field the proof-export correlation reasons about, where a missing
  // classification must be an explicit sentinel, not a null that compares
  // loosely. Lines written before this field existed have no env: the
  // correlation treats that absence as 'envUnknown' too.
  const env = keyEnv || 'envUnknown';
  let response;
  try { response = JSON.parse(respBuf.toString('utf8')); }
  catch (e) { response = { _unparsed: respBuf.toString('utf8').slice(0, 4000) }; }
  if (type === 'letter.create') {
    // The request blob was written durably at intent time (writeSendIntent), so
    // the outcome only references it by hash; it does not store it again. The
    // hash is deterministic over the same bytes, so this equals the intent's
    // requestBlob.
    const requestBlobSha256 = sha256Hex(reqBuf);
    auditAppend(dir, {
      type,
      status,
      // intentId links this outcome back to the write-ahead intent. An intent
      // with no matching outcome (see unresolvedIntents) is what the operator
      // must reconcile: we recorded that we were about to send, but never
      // recorded whether Lob accepted it.
      intentId: intentId || null,
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
      env,
      response,
    });
  } else if (type === 'letter.cancel') {
    const m = /\/v1\/letters\/(ltr_[A-Za-z0-9]+)/.exec(String(lobPath == null ? '' : lobPath).split('?')[0]);
    auditAppend(dir, { type, status, intentId: intentId || null, letterId: m ? m[1] : null, keyEnv, env, response });
  } else if (type === 'address.verify') {
    let addr = null;
    try {
      const b = JSON.parse(reqBuf.toString('utf8'));
      addr = { line1: b.primary_line, line2: b.secondary_line, city: b.city, state: b.state, zip: b.zip_code };
    } catch (e) { /* unparseable request body: leave addr null */ }
    auditAppend(dir, { type, status, addressSha256: addr ? addressHash(addr) : null, keyEnv, env, response });
  }
}

// Write-ahead intent for a mutating send (a letter create or cancel). Called
// BEFORE the request reaches Lob: it durably records that we are ABOUT to send,
// so a crash, a lost response, or a proxy timeout can never leave a send that
// happened at Lob with no local trace. Stores the exact request bytes as a blob
// (this is the single place the request-body blob is written) and appends a
// send.intent line naming it, then returns the new intentId. Any throw here
// propagates so the caller fails CLOSED and never contacts Lob: a send we could
// not durably record is a send we refuse to make. Blob first, then the line, so
// the referenced blob is always on disk before the line naming it.
function writeSendIntent(dir, params, now) {
  const { lobPath, reqHeaders, reqBuf } = params;
  const intentId = crypto.randomUUID();
  const requestBlob = blobStore(dir, reqBuf);
  auditAppend(dir, {
    type: 'send.intent',
    intentId,
    lobPath,
    fingerprint: firstHeader(reqHeaders['x-pd-fingerprint']),
    recipientHash: firstHeader(reqHeaders['x-pd-recipient-hash']),
    idempotencyKey: firstHeader(reqHeaders['idempotency-key']),
    // requestSha256 is the hash of the exact request bytes; requestBlob is the
    // content-addressed key they were stored under. Same value, named for both
    // roles (the commitment, and where to fetch the bytes back).
    requestSha256: requestBlob,
    requestBlob,
  }, now);
  return intentId;
}

// The substantive local-record events, newest first, as flat rows for the
// "Local record" UI. Pure derivation over the parsed lines: the durable actions
// this server took (sends, cancels, exports) and the operator's reconciliations.
// Raw send.intent lines are deliberately excluded: a resolved intent is
// represented by its outcome row, and an unresolved one by unresolvedIntents
// (the banner), so listing the intents here too would double-count. Every field
// is a primitive the UI escapes before rendering.
const LEDGER_TYPES = new Set(['letter.create', 'letter.cancel', 'proof.export', 'send.intent.resolved']);
function ledgerRows(lines) {
  const rows = [];
  for (const l of lines) {
    if (!LEDGER_TYPES.has(l.type)) continue;
    rows.push({
      ts: l.ts || null,
      type: l.type,
      letterId: l.letterId || null,
      status: (typeof l.status === 'number') ? l.status : null,
      keyEnv: l.keyEnv || null,
      // proof.export completeness (null for other rows), so the UI can flag a
      // partial evidentiary bundle without unzipping it.
      complete: l.type === 'proof.export' ? !!l.complete : null,
      // the operator's determination, for a send.intent.resolved row.
      resolution: l.resolution || null,
    });
  }
  return rows.reverse();  // newest first for display
}

// Intents with no recorded outcome and no manual resolution: the reconciliation
// worklist. An intent is resolved once a letter.create/letter.cancel outcome
// carrying its intentId lands (the normal path) OR an operator appends a
// send.intent.resolved for it. Everything else is a send whose fate is unknown
// and needs a human to check Lob. Pure derivation over the parsed lines. Returns
// oldest first (audit order), with only the fields the UI shows, never keys.
function unresolvedIntents(dir) {
  const lines = auditReadLines(dir);
  const intents = new Map();  // intentId -> the send.intent event
  const resolved = new Set(); // intentIds with an outcome or a manual resolution
  for (const l of lines) {
    if (l.type === 'send.intent' && l.intentId) intents.set(l.intentId, l);
    else if ((l.type === 'letter.create' || l.type === 'letter.cancel') && l.intentId) resolved.add(l.intentId);
    else if (l.type === 'send.intent.resolved' && l.intentId) resolved.add(l.intentId);
  }
  const out = [];
  for (const [id, ev] of intents) {
    if (resolved.has(id)) continue;
    out.push({
      intentId: id,
      ts: ev.ts || null,
      lobPath: ev.lobPath || null,
      fingerprint: ev.fingerprint || null,
      recipientHash: ev.recipientHash || null,
      idempotencyKey: ev.idempotencyKey || null,
      requestSha256: ev.requestSha256 || null,
    });
  }
  return out;
}

// Append an operator's manual resolution of an intent. Validates the resolution
// enum and (when present) the letter id, and refuses to record a resolution for
// an intent that does not exist so the log is not polluted with resolutions for
// unknown ids. Returns { ok, status, error } on rejection or { ok:true, event }
// on success. Append-only: a re-resolution is allowed (any resolution marks the
// intent resolved), so a corrected reconciliation is just another line.
function appendIntentResolution(dir, intentId, opts, now) {
  opts = opts || {};
  const resolution = opts.resolution;
  if (!INTENT_RESOLUTIONS.has(resolution)) {
    return { ok: false, status: 400, error: 'resolution must be one of: accepted, not_sent, unknown' };
  }
  let letterId = null;
  if (opts.letterId != null && opts.letterId !== '') {
    if (!LETTER_ID_RE.test(String(opts.letterId))) {
      return { ok: false, status: 400, error: 'Invalid letterId' };
    }
    letterId = String(opts.letterId);
  }
  // note is free operator text; bound its length so a resolution line cannot be
  // used to bloat the log.
  const note = opts.note == null ? null : String(opts.note).slice(0, 2000);
  const exists = auditReadLines(dir).some((l) => l.type === 'send.intent' && l.intentId === intentId);
  if (!exists) return { ok: false, status: 404, error: 'No such intent' };
  const event = { type: 'send.intent.resolved', intentId, resolution, letterId, note };
  auditAppend(dir, event, now);
  return { ok: true, event };
}

module.exports = {
  DATA_DIR, BLOB_RE, LETTER_ID_RE, INTENT_ID_RE,
  sha256Hex, writeDurable, normalizeAddressForHash, addressHash,
  ensureDataDir, auditAppend, auditVerifyChain, blobStore, blobPath, readBlob,
  auditReadLines, auditReadStats, auditQuery, findSendsByFingerprint,
  proxyAuditType, classifyProxyKeyEnv, firstHeader, captureProxyEvent,
  writeSendIntent, unresolvedIntents, appendIntentResolution, ledgerRows,
};
