'use strict';
// Login rate limiting (in-memory). Two parallel buckets, each
// LOGIN_MAX_ATTEMPTS failures per LOGIN_WINDOW_MS:
//   • by client IP  throttles a single source.
//   • by username   throttles guessing against one account even when many
//                   clients share a source IP (behind a proxy), so a spray of
//                   random usernames can't lock the real user out of their own
//                   account bucket.
// Enable PD_TRUST_PROXY (config.TRUST_PROXY) ONLY behind a trusted reverse
// proxy (Railway/Render/nginx); otherwise an attacker can forge XFF to mint
// unlimited fake client IPs and evade the per-IP limit entirely.
const {
  TRUST_PROXY, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_MS, ATTEMPT_MAP_MAX,
  FAIL_DELAY_SCHEDULE_MS, GLOBAL_FAIL_MAX, GLOBAL_FAIL_WINDOW_MS,
} = require('./config');

const ipAttempts = new Map();   // ip       -> { count, first }
const userAttempts = new Map(); // username -> { count, first }

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = req.headers['x-forwarded-for'];
    if (xff) { const first = String(xff).split(',')[0].trim(); if (first) return ipBucket(first); }
  }
  return ipBucket(req.socket.remoteAddress || 'unknown');
}

// Parse an IPv6 literal into its 8 sixteen-bit groups, or return null if it is
// not a valid IPv6 literal (so callers can leave garbage untouched, never throw).
// Handles '::' compression, an embedded IPv4 tail (a.b.c.d in the last 32 bits),
// and a %zone suffix (dropped: a zone id names a link, not the address).
function ipv6ToGroups(input) {
  let s = String(input == null ? '' : input);
  const pct = s.indexOf('%');
  if (pct !== -1) s = s.slice(0, pct);
  if (s.indexOf(':') === -1) return null;              // not IPv6
  // Fold an embedded IPv4 tail into two hex groups.
  if (s.indexOf('.') !== -1) {
    const idx = s.lastIndexOf(':');
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s.slice(idx + 1));
    if (!m) return null;
    const o = [+m[1], +m[2], +m[3], +m[4]];
    if (o.some((x) => x > 255)) return null;
    s = s.slice(0, idx + 1) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  // Expand a single '::' into the right number of zero groups.
  let groups;
  const dbl = s.indexOf('::');
  if (dbl !== -1) {
    if (s.indexOf('::', dbl + 1) !== -1) return null;  // at most one '::'
    const head = s.slice(0, dbl) === '' ? [] : s.slice(0, dbl).split(':');
    const tail = s.slice(dbl + 2) === '' ? [] : s.slice(dbl + 2).split(':');
    const missing = 8 - (head.length + tail.length);
    if (missing < 1) return null;                      // '::' must stand for >=1 zero group
    groups = head.concat(Array(missing).fill('0'), tail);
  } else {
    groups = s.split(':');
  }
  if (groups.length !== 8) return null;
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

// Render 8 groups as RFC 5952 canonical text: lowercase, no leading zeros, and
// the LONGEST run of >=2 zero groups collapsed to '::' (leftmost run wins a tie).
function rfc5952(g) {
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === 0) {
      if (curStart === -1) { curStart = i; curLen = 1; } else curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  const hex = g.map((x) => x.toString(16));
  if (bestLen < 2) return hex.join(':');               // no compression for a single zero
  return hex.slice(0, bestStart).join(':') + '::' + hex.slice(bestStart + bestLen).join(':');
}

// Canonicalize an address to ONE textual form so the same host never wears two
// keys. Pure and total: valid IPv6 becomes RFC 5952 text, an IPv4-mapped
// ::ffff:a.b.c.d becomes dotted a.b.c.d (it identifies an IPv4 client), IPv4 and
// anything that is not a valid IP pass through unchanged (never throws).
function canonicalizeIp(addr) {
  const raw = String(addr == null ? '' : addr);
  if (raw.indexOf(':') === -1) return raw;             // IPv4 or a non-IP token: as-is
  const g = ipv6ToGroups(raw);
  if (!g) return raw;                                  // not valid IPv6: leave unchanged
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return ((g[6] >> 8) & 0xff) + '.' + (g[6] & 0xff) + '.' + ((g[7] >> 8) & 0xff) + '.' + (g[7] & 0xff);
  }
  return rfc5952(g);
}

// The per-IP bucket key. A single IPv6 allocation routinely hands out a whole
// /64, so keying on the full address lets an attacker mint unlimited distinct
// keys and sail past the per-IP cap; keying on the /64 throttles the allocation
// as one source. The /64 is computed AFTER canonicalization, so every textual
// form of the same prefix (compressed, expanded, mixed case, leading zeros) maps
// to ONE key. IPv4 (and an IPv4-mapped address, which canonicalizes to dotted
// IPv4) is keyed on the full address; garbage is keyed on itself, unchanged.
function ipBucket(addr) {
  const canon = canonicalizeIp(addr || 'unknown');
  if (canon.indexOf(':') === -1) return canon;         // IPv4, mapped-to-v4, 'unknown', or garbage
  const g = ipv6ToGroups(canon);
  if (!g) return canon;                                // defensive: canonical IPv6 always reparses
  return rfc5952([g[0], g[1], g[2], g[3], 0, 0, 0, 0]) + '/64';
}

// Canonicalize a bucket key: trim and truncate. Applied to the username before
// EVERY attemptBlocked / recordAttempt / clearAttempts call so all three see
// the same key. The why: the login body allows up to 16 KB and the cleanup
// sweep only runs every 15 minutes, so unbounded attacker-chosen keys are a
// memory-growth vector between sweeps.
function bucketKey(raw, maxLen) {
  return String(raw == null ? '' : raw).trim().slice(0, maxLen);
}

function attemptBlocked(map, key) {
  const rec = map.get(key);
  if (!rec) return false;
  if (Date.now() - rec.first > LOGIN_WINDOW_MS) { map.delete(key); return false; }
  return rec.count >= LOGIN_MAX_ATTEMPTS;
}

function recordAttempt(map, key) {
  const rec = map.get(key);
  if (!rec || Date.now() - rec.first > LOGIN_WINDOW_MS) {
    // Refuse to insert a NEW key once the map is at the cap (existing keys,
    // including expired ones being reset, still update). The why: the per-IP
    // bucket still throttles whoever is spraying, so degrading the username
    // bucket under flood is the safe failure mode, versus unbounded memory.
    if (!rec && map.size >= ATTEMPT_MAP_MAX) return;
    map.set(key, { count: 1, first: Date.now() });
  } else {
    rec.count += 1;
  }
}

function clearAttempts(map, key) { map.delete(key); }

// ── Progressive failure delay + global failure throttle ──
// Two layers on top of the buckets above. Neither layer ever gates credential
// evaluation (see the anti-lockout comment in the login route): they only
// shape how attempts that were ALREADY evaluated as failed are answered.

// Decide how to answer an evaluated login attempt. Pure: counters go in, the
// successor global state comes out, and time is the injected now, so unit
// tests drive the clock and never sleep. keyFailures is the consecutive
// failure count for this attempt's bucket key INCLUDING this attempt
// (successes clear the buckets, so a bucket count IS the consecutive-failure
// count within the window). Returns one of:
//   { action: 'allow' }     correct password: never delayed, never throttled
//   { action: 'throttle' }  global ceiling hit: fast uniform 429
//   { action: 'delay' }     failure: respond after delayMs per the schedule
function loginThrottleDecision(outcome, global, keyFailures, now) {
  if (outcome === 'ok') return { action: 'allow', delayMs: 0, global };
  const g = (global.count > 0 && now - global.first > GLOBAL_FAIL_WINDOW_MS)
    ? { count: 0, first: 0 }
    : global;
  if (g.count >= GLOBAL_FAIL_MAX) {
    // No delay once tripped: sleeping here would let a flood use the delay
    // itself to pin open sockets, so the rejection must be fast.
    return { action: 'throttle', delayMs: 0, global: g };
  }
  const idx = Math.min(Math.max(keyFailures, 1), FAIL_DELAY_SCHEDULE_MS.length) - 1;
  return {
    action: 'delay',
    delayMs: FAIL_DELAY_SCHEDULE_MS[idx],
    global: { count: g.count + 1, first: g.count === 0 ? now : g.first },
  };
}

// Real sleep for the failure delay, held in a swappable holder so tests can
// observe requested delays without actually sleeping through the schedule.
const loginFailureDelay = {
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

// Prevent unbounded growth: periodically drop expired records from both buckets.
// unref() so this timer never keeps the process alive on its own (this preserves
// the inert-on-require property: no bind, no I/O, no blocking).
setInterval(() => {
  const now = Date.now();
  for (const map of [ipAttempts, userAttempts]) {
    for (const [key, rec] of map) {
      if (now - rec.first > LOGIN_WINDOW_MS) map.delete(key);
    }
  }
}, LOGIN_WINDOW_MS).unref();

module.exports = {
  ipAttempts, userAttempts,
  clientIp, ipBucket, canonicalizeIp, bucketKey,
  attemptBlocked, recordAttempt, clearAttempts,
  loginThrottleDecision, loginFailureDelay,
};
