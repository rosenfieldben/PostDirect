'use strict';
// Configuration: every env-derived constant plus the pure startup validator.
// Reading process.env here is the only "side effect", and it is pure string
// work (no filesystem, no network, no bind), so requiring this module stays
// inert. Other lib modules import their constants from here.
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');

// ══════════════════════════════════════════════════════════════
// CONFIGURATION, set these via environment variables
// ══════════════════════════════════════════════════════════════
const PORT = parseInt(process.env.PORT || '3491', 10);
const USERNAME = process.env.PD_USERNAME || 'admin';
const PASSWORD = process.env.PD_PASSWORD || 'changeme';
const SECRET_FROM_ENV = !!process.env.PD_SECRET;
const SESSION_SECRET = process.env.PD_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME = 'pd_session';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

// Optional server-side Lob API key. When set, the browser never needs to see
// the key: the proxy injects it into any upstream request that doesn't carry
// its own Authorization header. A key pasted into the UI still wins, so
// switching to a different test/live key doesn't require a redeploy.
const LOB_KEY = (process.env.PD_LOB_KEY || '').trim();
// Lob keys are 'test_…' or 'live_…'. Anything unrecognized is reported as
// 'live' so the UI errs toward the scary red live-mode treatment: showing
// "Test" for a key that actually spends postage is the failure mode to avoid.
// (Lives here rather than in proxy.js so config can compute LOB_KEY_ENV without
// a config -> proxy require, and so store.js can classify without a
// store -> proxy cycle. There is still exactly ONE server-side classifier.)
function lobKeyEnv(key) {
  const k = (key == null ? '' : String(key)).trim();
  if (!k) return null;
  return k.startsWith('test_') ? 'test' : 'live';
}
const LOB_KEY_ENV = lobKeyEnv(LOB_KEY);

// Upstream Lob API target. Defaults to Lob over HTTPS and is NEVER derived from
// client input, so the no-SSRF / no-open-proxy property holds: a request can
// only ever reach this one operator-configured origin. PD_LOB_UPSTREAM exists to
// point the proxy at a local stub for integration tests (operator-only config,
// same trust level as PD_LOB_KEY); malformed values fall back to Lob.
const LOB_UPSTREAM = (() => {
  const fallback = { hostname: 'api.lob.com', port: 443, transport: https };
  const raw = (process.env.PD_LOB_UPSTREAM || '').trim();
  if (!raw) return fallback;
  try {
    const u = new URL(raw);
    const isHttp = u.protocol === 'http:';
    return {
      hostname: u.hostname,
      port: u.port ? parseInt(u.port, 10) : (isHttp ? 80 : 443),
      transport: isHttp ? http : https,
    };
  } catch (e) { return fallback; }
})();

// Request body size limits (bytes)
const LOGIN_BODY_LIMIT = 16 * 1024;          // 16 KB, the login form is tiny
const PROXY_BODY_LIMIT = 52 * 1024 * 1024;   // 52 MB, headroom over the 50 MB PDF cap + multipart overhead
const PROXY_TIMEOUT_MS = 30 * 1000;          // 30 s, upstream Lob request timeout

// Login rate limiting (per-IP, in-memory)
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;      // 15 minutes
const BUCKET_KEY_MAX = 256;                  // max chars of a username used as a bucket key
const ATTEMPT_MAP_MAX = 10000;               // max distinct keys per bucket between sweeps
// Progressive failure delay, indexed by consecutive failures for a key: the
// first failure answers immediately, then 0.5s/1s/2s, capped at 4s. The cap
// keeps a slow-guess response from becoming a socket-holding primitive while
// still slowing an online guesser by orders of magnitude; a fat-fingered
// human retyping a password barely notices. Failure responses only: a
// correct password is never delayed.
const FAIL_DELAY_SCHEDULE_MS = [0, 500, 1000, 2000, 4000];
// Global failure throttle: a process-wide ceiling on FAILED attempts per
// window across ALL bucket keys, so rotating IPs or mangling the username
// (a fresh bucket key every attempt) cannot buy unlimited tries. 50 per
// window is far above any legitimate typo rate and far below a useful
// online guessing rate.
const GLOBAL_FAIL_MAX = 50;
const GLOBAL_FAIL_WINDOW_MS = LOGIN_WINDOW_MS; // one window size everywhere

// IP derivation: key on the socket address by default. X-Forwarded-For is
// client-spoofable, so it is trusted ONLY when PD_TRUST_PROXY is explicitly set.
const TRUST_PROXY = (() => { const v = (process.env.PD_TRUST_PROXY || '').toLowerCase(); return v === '1' || v === 'true'; })();

// ══════════════════════════════════════════════════════════════
// STARTUP VALIDATION
// ══════════════════════════════════════════════════════════════
// Startup failures are fatal, request failures are not: the per-request
// catch-all keeps a RUNNING server alive, but a server that cannot start must
// exit nonzero, or a supervisor sees a clean exit from a process that never
// bound its port. Pure function of an env object so tests cover every path
// without booting a process.
function validateStartupConfig(env) {
  const errors = [];
  const rawPort = env.PORT || '3491';
  // parseInt (which the PORT constant uses) would accept "80abc" as 80, so
  // require the whole value to be digits before the range check.
  if (!/^[0-9]+$/.test(String(rawPort).trim()) || +rawPort < 1 || +rawPort > 65535) {
    errors.push('PORT must be an integer between 1 and 65535 (got "' + rawPort + '")');
  }
  // PD_INSECURE_LOCAL_DEMO=1 is the single escape hatch for local demos: it
  // permits default/weak credentials but forces a loopback-only bind, so the
  // demo server is never reachable from another machine.
  const insecureDemo = env.PD_INSECURE_LOCAL_DEMO === '1';
  if (!insecureDemo) {
    // These floors apply under EVERY NODE_ENV value, including unset: the old
    // guard fired only when NODE_ENV was exactly 'production', so a missing
    // or mistyped NODE_ENV booted a reachable server on admin/changeme.
    if (!env.PD_USERNAME || env.PD_USERNAME === 'admin') {
      errors.push('PD_USERNAME is unset or the shipped default ("admin"); set a real username');
    }
    if (!env.PD_PASSWORD || env.PD_PASSWORD === 'changeme') {
      errors.push('PD_PASSWORD is unset or the shipped default ("changeme"); set a real password');
    } else if (env.PD_PASSWORD.length < 12) {
      // 12-character floor: credential evaluation is deliberately never gated
      // on rate-limit state (anti-lockout), so password entropy is the real
      // barrier against patient online guessing.
      errors.push('PD_PASSWORD must be at least 12 characters (got ' + env.PD_PASSWORD.length + ')');
    }
    if (!env.PD_SECRET) {
      errors.push('PD_SECRET is unset; set a stable random string (e.g. openssl rand -hex 32)');
    } else if (env.PD_SECRET.length < 32) {
      // 32-character floor: PD_SECRET keys the HMAC that makes session
      // cookies unforgeable, and a short secret makes those signatures
      // brute-forceable offline.
      errors.push('PD_SECRET must be at least 32 characters (got ' + env.PD_SECRET.length + ')');
    }
  }
  return {
    ok: errors.length === 0,
    errors,
    insecureDemo,
    // undefined means "all interfaces" (server.listen's default)
    host: insecureDemo ? '127.0.0.1' : undefined,
  };
}

module.exports = {
  PORT, USERNAME, PASSWORD, SECRET_FROM_ENV, SESSION_SECRET, COOKIE_NAME, SESSION_MAX_AGE,
  LOB_KEY, lobKeyEnv, LOB_KEY_ENV, LOB_UPSTREAM,
  LOGIN_BODY_LIMIT, PROXY_BODY_LIMIT, PROXY_TIMEOUT_MS,
  LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_MS, BUCKET_KEY_MAX, ATTEMPT_MAP_MAX,
  FAIL_DELAY_SCHEDULE_MS, GLOBAL_FAIL_MAX, GLOBAL_FAIL_WINDOW_MS, TRUST_PROXY,
  validateStartupConfig,
};
