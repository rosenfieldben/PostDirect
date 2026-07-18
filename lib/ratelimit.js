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

// Collapse an IPv6 address to its /64 prefix for the per-IP bucket key. A single
// allocation routinely hands out a whole /64, so keying on the full address lets
// an attacker mint unlimited distinct keys and sail past the per-IP cap; keying
// on the /64 throttles the allocation as one source. IPv4 is returned as-is.
function ipBucket(addr) {
  let a = String(addr || 'unknown');
  if (a.indexOf(':') === -1) return a;                 // IPv4 (or 'unknown')
  if (a.lastIndexOf(':') > a.indexOf('.') && a.indexOf('.') !== -1) {
    // IPv4-mapped IPv6 (e.g. ::ffff:1.2.3.4): key on the embedded IPv4.
    return a.slice(a.lastIndexOf(':') + 1);
  }
  const hextets = a.split(':');
  // Take the first four 16-bit groups (the /64 network prefix). '::' shorthand
  // yields empty strings, which is fine: same collapsed prefix per source.
  return hextets.slice(0, 4).join(':') + '::/64';
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
  clientIp, ipBucket, bucketKey,
  attemptBlocked, recordAttempt, clearAttempts,
  loginThrottleDecision, loginFailureDelay,
};
