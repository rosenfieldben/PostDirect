'use strict';
// Durable, fingerprint-keyed idempotency (Web Crypto global; storage injected).
// Extracted verbatim from the former inline <script> in public/index.html so
// the browser app and the Node unit tests share ONE source of truth (the unit
// tests import this module directly instead of re-parsing the HTML).

  // Durable idempotency: Lob Idempotency-Key values are persisted in
  // localStorage keyed by a content FINGERPRINT (normalized recipient + shared
  // options + uploaded-file hash), not by an in-memory recipient id. The old
  // in-memory Map was discarded on reload/crash/closed-tab, after which
  // resubmitting the same letter created duplicate physical mail. Now a reload
  // followed by an identical resubmit reuses the same key within Lob's 24h
  // window, so Lob de-dupes instead of printing twice. See the persistence
  // helpers below (getOrCreatePersistedKey, pruneIdempotencyStore).
  const IDEMPOTENCY_STORE_KEY = 'pd_idempotency_v1';

  const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000; // Lob honors an idempotency key for 24 hours

  // ═══ Durable idempotency + content fingerprint ═══
  // Canonical string over the normalized recipient, the shared send options,
  // and the uploaded-file hash. Named + pure so the extraction harness can pin
  // its stability: sorted keys and trimmed strings mean the SAME logical letter
  // always produces the SAME string (and therefore the same fingerprint),
  // regardless of key order or incidental whitespace.
  function canonicalizeSendInput(recipient, options, fileHashHex) {
    const trim = (val) => String(val == null ? '' : val).trim();
    const sortTrim = (obj) => {
      const out = {};
      Object.keys(obj || {}).sort().forEach((k) => { out[k] = trim(obj[k]); });
      return out;
    };
    // options may arrive as commonLetterFields' array of [key, value] pairs or
    // as a plain object; normalize both to a sorted, trimmed object.
    let optObj = {};
    if (Array.isArray(options)) options.forEach((pair) => { optObj[pair[0]] = pair[1]; });
    else optObj = Object.assign({}, options);
    return JSON.stringify({
      recipient: sortTrim(recipient || {}),
      options: sortTrim(optObj),
      file: String(fileHashHex == null ? '' : fileHashHex),
    });
  }

  // SHA-256 hex of a BufferSource via Web Crypto (available in the browser; in
  // the Node extraction tests the harness injects crypto).
  async function sha256HexOf(data) {
    const digest = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  async function computeFingerprint(recipient, options, fileHashHex) {
    return sha256HexOf(new TextEncoder().encode(canonicalizeSendInput(recipient, options, fileHashHex)));
  }

  // Drop entries older than the 24h window (pure). Called on every load so the
  // store never grows without bound and a stale key is never reused.
  function pruneIdempotencyStore(store, now) {
    const out = {};
    Object.keys(store || {}).forEach((fp) => {
      const rec = store[fp];
      if (rec && typeof rec.createdAt === 'number' && (now - rec.createdAt) < IDEMPOTENCY_TTL_MS) out[fp] = rec;
    });
    return out;
  }

  function loadIdempotencyStore(storage, now) {
    let parsed = {};
    try { parsed = JSON.parse(storage.getItem(IDEMPOTENCY_STORE_KEY) || '{}') || {}; } catch (e) { parsed = {}; }
    return pruneIdempotencyStore(parsed, now);
  }

  function saveIdempotencyStore(storage, store) {
    try { storage.setItem(IDEMPOTENCY_STORE_KEY, JSON.stringify(store)); } catch (e) { /* storage full/unavailable: best effort */ }
  }

  // Reuse the persisted key for this fingerprint within the window, or mint and
  // persist one BEFORE the send fires, so an interrupted send is safe to retry.
  function getOrCreatePersistedKey(storage, fingerprint, now, uuidFn) {
    const store = loadIdempotencyStore(storage, now);
    let rec = store[fingerprint];
    if (!rec) {
      rec = { idempotencyKey: uuidFn(), createdAt: now };
      store[fingerprint] = rec;
      saveIdempotencyStore(storage, store);
    }
    return rec;
  }

  // Note the resulting letter id on the persisted record (best effort).
  function recordSentLetter(storage, fingerprint, letterId, now) {
    const store = loadIdempotencyStore(storage, now);
    if (store[fingerprint]) { store[fingerprint].letterId = letterId; saveIdempotencyStore(storage, store); }
  }

export { IDEMPOTENCY_STORE_KEY, IDEMPOTENCY_TTL_MS, canonicalizeSendInput, sha256HexOf, computeFingerprint, pruneIdempotencyStore, loadIdempotencyStore, saveIdempotencyStore, getOrCreatePersistedKey, recordSentLetter };
