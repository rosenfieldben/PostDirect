const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { pipeline } = require('stream');
 
// ══════════════════════════════════════════════════════════════
// CONFIGURATION — set these via environment variables
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
// 'live' so the UI errs toward the scary red live-mode treatment — showing
// "Test" for a key that actually spends postage is the failure mode to avoid.
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
const LOGIN_BODY_LIMIT = 16 * 1024;          // 16 KB — the login form is tiny
const PROXY_BODY_LIMIT = 52 * 1024 * 1024;   // 52 MB — headroom over the 50 MB PDF cap + multipart overhead
const PROXY_TIMEOUT_MS = 30 * 1000;          // 30 s — upstream Lob request timeout

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
 
// ══════════════════════════════════════════════════════════════
// STATELESS SESSIONS — HMAC-signed cookies, no server-side store
// ══════════════════════════════════════════════════════════════
// The cookie value is `<issuedAt>.<signature>` where signature =
// HMAC-SHA256(PD_SECRET, issuedAt). There is no server-side store, so
// sessions survive restarts — but ONLY if PD_SECRET is stable across
// restarts (a random per-process fallback invalidates them; see the
// startup warning). Stateless sessions cannot be revoked server-side;
// logout simply clears the cookie.
function signValue(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
}

function createSession() {
  const issuedAt = Date.now().toString();
  return issuedAt + '.' + signValue(issuedAt);
}

function validateSession(token) {
  if (!token) return false;
  const dot = token.indexOf('.');
  if (dot < 1) return false;
  const issuedAt = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^[0-9]+$/.test(issuedAt) || !/^[0-9a-f]+$/.test(sig)) return false;
  const expected = signValue(issuedAt);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  if (!crypto.timingSafeEqual(a, b)) return false;
  if (Date.now() - parseInt(issuedAt, 10) > SESSION_MAX_AGE) return false;
  return true;
}
 
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(c => { const [k, ...v] = c.split('='); if (k) cookies[k.trim()] = v.join('=').trim(); });
  return cookies;
}
 
function getSessionToken(req) {
  return parseCookies(req.headers.cookie)[COOKIE_NAME] || null;
}
 
// Whether the session cookie should carry the Secure attribute.
// PD_SECURE_COOKIES=1/0 forces on/off; otherwise auto-detect from the
// X-Forwarded-Proto header set by a TLS-terminating reverse proxy.
function isSecure(req) {
  const env = process.env.PD_SECURE_COOKIES;
  if (env === '1' || env === 'true') return true;
  if (env === '0' || env === 'false') return false;
  return (req.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase() === 'https';
}

function setCookie(res, token, secure) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE / 1000}${secure ? '; Secure' : ''}`);
}

function clearCookie(res, secure) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure ? '; Secure' : ''}`);
}
 
// ══════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════
function readBody(req, res, maxBytes) {
  return new Promise((resolve) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    const done = (val) => { if (!settled) { settled = true; resolve(val); } };
    req.on('data', (c) => {
      total += c.length;
      if (total > maxBytes) {
        if (res && !res.headersSent) {
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'Request body too large' } }));
        }
        req.destroy();
        return done(null);
      }
      chunks.push(c);
    });
    req.on('end', () => done(Buffer.concat(chunks)));
    req.on('error', () => {
      if (res && !res.headersSent) { try { res.writeHead(400); res.end(); } catch (e) { /* ignore */ } }
      done(null);
    });
    // Settle on teardown too: a client that sends headers then aborts (or goes
    // half-open) may never emit 'end' or 'error', which would leave this promise
    // — and its awaiting handler — dangling. 'close' fires after 'end' as well,
    // but done() is idempotent so the normal path already resolved by then.
    req.on('close', () => done(null));
  });
}

// Authorization header the proxy sends upstream to Lob: the client's own
// header when present (a key pasted into the UI overrides the server key),
// else Basic auth minted from PD_LOB_KEY, else nothing (Lob replies 401).
function lobAuthorization(clientAuth) {
  if (clientAuth) return clientAuth;
  if (LOB_KEY) return 'Basic ' + Buffer.from(LOB_KEY + ':').toString('base64');
  return undefined;
}

// Constant-time credential comparison (hash first so unequal lengths
// don't throw and length isn't leaked via early exit).
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// ── Login rate limiting (in-memory) ──
// Two parallel buckets, each LOGIN_MAX_ATTEMPTS failures per LOGIN_WINDOW_MS:
//   • by client IP  — throttles a single source.
//   • by username   — throttles guessing against one account even when many
//                     clients share a source IP (behind a proxy), so a spray of
//                     random usernames can't lock the real user out of their own
//                     account bucket.
// IP derivation: we key on the socket address by default. X-Forwarded-For is
// client-spoofable, so it is trusted ONLY when PD_TRUST_PROXY is explicitly set.
// Enable PD_TRUST_PROXY ONLY when the app genuinely sits behind a trusted reverse
// proxy (Railway/Render/nginx); otherwise an attacker can forge XFF to mint
// unlimited fake client IPs and evade the per-IP limit entirely.
const TRUST_PROXY = (() => { const v = (process.env.PD_TRUST_PROXY || '').toLowerCase(); return v === '1' || v === 'true'; })();
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
  // yields empty strings, which is fine — same collapsed prefix per source.
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
let globalFailures = { count: 0, first: 0 };  // process-wide failed-attempt window

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
// unref() so this timer never keeps the process alive on its own.
setInterval(() => {
  const now = Date.now();
  for (const map of [ipAttempts, userAttempts]) {
    for (const [key, rec] of map) {
      if (now - rec.first > LOGIN_WINDOW_MS) map.delete(key);
    }
  }
}, LOGIN_WINDOW_MS).unref();
 
// Minimal HTML escaper for values interpolated into a page template. Every
// current loginPage(error) caller passes a static string, so this is
// defense-in-depth: it removes the footgun so a future caller that forwards
// user input (e.g. echoing a submitted username) can't introduce reflected XSS.
const HTML_ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
function escapeHtml(s) { return (s == null ? '' : String(s)).replace(/[&<>"']/g, (c) => HTML_ESC[c]); }

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(body);
}
 
function sendHTML(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}
 
function redirect(res, url) {
  res.writeHead(302, { 'Location': url });
  res.end();
}

// Security headers applied to EVERY response. Set via setHeader() at the top of
// the request handler so they persist through every later writeHead()/pipe()
// (writeHead merges with, and only overrides on name collision — none here).
// The CSP is deliberately permissive enough not to break the app: inline
// <style>/<script>, Google Fonts (CSS from fonts.googleapis.com + font files
// from fonts.gstatic.com), data: URIs in CSS, and same-origin fetch to /api/lob.
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";
function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', CSP);
}
 
// ══════════════════════════════════════════════════════════════
// STATIC FILES
// ══════════════════════════════════════════════════════════════
const STATIC_DIR = path.join(__dirname, 'public');
const MIME_TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
 
function serveStatic(res, filePath) {
  const full = path.join(STATIC_DIR, filePath);
  if (full !== STATIC_DIR && !full.startsWith(STATIC_DIR + path.sep)) { res.writeHead(403); res.end(); return; }
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(full);
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(data);
  });
}
 
// ══════════════════════════════════════════════════════════════
// LOGIN PAGE (minimalist light / firm-professional)
// ══════════════════════════════════════════════════════════════
function loginPage(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PostDirect — Sign In</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,500;0,8..60,600;0,8..60,700&display=swap" rel="stylesheet">
<style>
  :root {
    /* Deep navy backdrop falling to ink black (matches the app's ink-950) */
    --bg: #05070c;
    --bg-grad: radial-gradient(1200px 720px at 50% -280px, #16315f 0%, #0e2147 44%, #05070c 100%);
    --surface: #ffffff;
    --surface-warm: #f4f7fc;
    --ink: #0c1c3a;
    --text: #28324a;
    --text-dim: #586079;
    --text-muted: #6b748b;
    --border: #dfe4ee;
    --border-strong: #c5cdde;
    --border-soft: #eaeef5;
    --hairline: rgba(12,28,58,0.08);
    --focus-ring: 0 0 0 3px rgba(47,109,240,0.22);
    --cobalt: #2f6df0;
    --accent: #f4a92b;
    --gold: #9a6a14;
    --success: #0f7a52;
    /* danger is the wax family (matches the app's live/error red) */
    --danger: #8c2318;
    --danger-bg: #f9eceb;
    --danger-border: rgba(140,35,24,0.28);
    --white: #ffffff;
    --brand-grad: linear-gradient(135deg, #1c3f7e 0%, #0e2147 56%, #05070c 100%);
    --shadow-xs: 0 1px 2px rgba(12,28,58,0.06);
    --shadow-lg: 0 18px 50px rgba(4,10,26,0.45), 0 4px 14px rgba(4,10,26,0.30);
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg);
    background-image: var(--bg-grad);
    background-attachment: fixed;
    color: var(--text);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    padding: 24px;
    line-height: 1.5;
  }
  .login-card {
    width: 100%;
    max-width: 420px;
    padding: 46px 44px 34px;
    background: var(--surface);
    border: 1px solid rgba(255,255,255,0.6);
    border-radius: 18px;
    box-shadow: var(--shadow-lg);
    position: relative;
    overflow: hidden;
  }
  .login-card::before {
    content: "";
    position: absolute;
    left: 0; right: 0; top: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--cobalt) 0%, var(--accent) 100%);
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
    justify-content: center;
    position: relative;
  }
  .brand-mark-wrap {
    width: 40px; height: 40px;
    border-radius: 11px;
    background: var(--brand-grad);
    color: #eaf1ff;
    display: inline-flex; align-items: center; justify-content: center;
    box-shadow: 0 1px 0 rgba(255,255,255,0.14) inset, 0 6px 16px rgba(12,28,58,0.28);
    position: relative;
  }
  .brand-mark-wrap::after {
    content: ""; position: absolute; right: -3px; top: -3px;
    width: 9px; height: 9px; border-radius: 50%;
    background: var(--accent); box-shadow: 0 0 0 2px var(--surface), 0 0 10px rgba(244,169,43,0.55);
  }
  .brand-mark { width: 21px; height: 21px; }
  .brand-name { font-family: 'Source Serif 4', Georgia, serif; font-weight: 600; font-size: 25px; color: var(--ink); letter-spacing: -0.02em; }
  .brand-sub {
    text-align: center;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 38px;
    position: relative;
  }
  .brand-sub::before, .brand-sub::after {
    content: "";
    display: inline-block;
    width: 22px; height: 1px;
    background: var(--border);
    vertical-align: middle;
    margin: 0 12px;
  }
  .field { margin-bottom: 18px; position: relative; }
  .field-label {
    display: block;
    margin-bottom: 8px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.11em;
    color: var(--text-dim);
  }
  .field-input {
    width: 100%;
    padding: 12px 14px;
    border: 1px solid var(--border);
    border-radius: 9px;
    font-size: 14px;
    font-family: 'Inter', sans-serif;
    background: var(--surface-warm);
    color: var(--text);
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s, background 0.15s;
    box-shadow: var(--shadow-xs);
  }
  .field-input:hover { border-color: var(--border-strong); }
  .field-input:focus { border-color: var(--cobalt); box-shadow: var(--focus-ring); background: var(--surface); }
  .btn {
    width: 100%;
    padding: 13px;
    border-radius: 10px;
    font-size: 13.5px;
    font-weight: 600;
    font-family: 'Inter', sans-serif;
    cursor: pointer;
    border: 1px solid transparent;
    background: var(--brand-grad);
    color: var(--white);
    transition: all 0.18s ease;
    margin-top: 16px;
    box-shadow: 0 1px 0 rgba(255,255,255,0.12) inset, 0 2px 6px rgba(12,28,58,0.20), 0 8px 18px rgba(14,33,71,0.20);
    letter-spacing: 0.02em;
  }
  .btn:hover {
    transform: translateY(-1px);
    box-shadow: 0 1px 0 rgba(255,255,255,0.16) inset, 0 4px 10px rgba(12,28,58,0.24), 0 12px 26px rgba(31,80,201,0.28);
  }
  .btn:active { transform: translateY(0); }
  .error {
    padding: 11px 14px;
    border-radius: 9px;
    background: var(--danger-bg);
    border: 1px solid var(--danger-border);
    color: var(--danger);
    font-size: 13px;
    margin-bottom: 20px;
    text-align: center;
    font-weight: 500;
  }
  .footer {
    text-align: center;
    margin-top: 30px;
    padding-top: 22px;
    border-top: 1px solid var(--border-soft);
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    justify-content: center;
  }
  .footer::before {
    content: "";
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 0 3px rgba(15,122,82,0.18);
  }
</style>
</head>
<body>
<div class="login-card">
  <div class="brand">
    <span class="brand-mark-wrap" aria-hidden="true">
      <svg class="brand-mark" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="3" y="6" width="18" height="13" rx="1.4" stroke="currentColor" stroke-width="1.5"/>
        <path d="M3.5 7.2l8.5 6 8.5-6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </span>
    <div class="brand-name">PostDirect</div>
  </div>
  <div class="brand-sub">Physical mail · USPS</div>
  ${error ? '<div class="error">' + escapeHtml(error) + '</div>' : ''}
  <form method="POST" action="/login">
    <div class="field">
      <label class="field-label" for="username">Username</label>
      <input class="field-input" type="text" name="username" id="username" autocomplete="username" required autofocus />
    </div>
    <div class="field">
      <label class="field-label" for="password">Password</label>
      <input class="field-input" type="password" name="password" id="password" autocomplete="current-password" required />
    </div>
    <button class="btn" type="submit">Sign In</button>
  </form>
  <div class="footer">Secured access</div>
</div>
</body>
</html>`;
}
 
// ══════════════════════════════════════════════════════════════
// PERSISTENCE: append-only audit log + content-addressed blobs
// ══════════════════════════════════════════════════════════════
// The server was a stateless proxy: nothing about a send survived the process,
// so the operator could not prove what was sent, when, or with which key
// environment, and Lob retains mailpiece data for only 90 days. This store is
// the durable system of record under PD_DATA_DIR:
//   • audit.log  append-only JSONL, one self-contained event per line, written
//                with a SYNCHRONOUS append so the line is on disk before the
//                response that reports it. No line is ever rewritten or deleted.
//   • blobs/     content-addressed raw bytes at blobs/<sha256hex>, written once.
// Every store function takes the data directory explicitly (dependency
// injection), so tests run against a fresh fs.mkdtemp dir. Nothing here runs at
// module load: the directory is created at the entrypoint (ensureDataDir) or
// lazily on first write, so REQUIRING this module creates no directories.

// PD_DATA_DIR default lives beside server.js, never inside public/, so it is
// never web-served (serveStatic only serves STATIC_DIR). Resolved at load time,
// but this is pure string work: no filesystem touch happens here.
const DATA_DIR = path.resolve(process.env.PD_DATA_DIR || path.join(__dirname, 'data'));
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

// Create the data directory tree (mode 0700: it holds client PII and mailed
// documents) and prove it is writable. Returns {ok} or {ok:false, error}. Fatal
// at startup, and also called lazily by the writers so tests that never boot
// the entrypoint still work (first-use creation, not module-load).
function ensureDataDir(dir) {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(dir, 'blobs'), { recursive: true, mode: 0o700 });
    // Writability probe: mkdir succeeds on a read-only dir when running as root,
    // so write (then remove) a real file to catch a genuinely unwritable target.
    const probe = path.join(dir, '.pd-write-test');
    fs.writeFileSync(probe, '');
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
  fs.appendFileSync(path.join(dir, 'audit.log'), line);
  return line;
}

// Content-addressed write: bytes land at blobs/<sha256hex>, written once with
// the wx flag so identical content dedupes and an existing blob is never
// rewritten. Returns the hash.
function blobStore(dir, buf) {
  const hex = sha256Hex(buf);
  const blobsDir = path.join(dir, 'blobs');
  fs.mkdirSync(blobsDir, { recursive: true, mode: 0o700 });
  try { fs.writeFileSync(path.join(blobsDir, hex), buf, { flag: 'wx' }); }
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

// Read audit.log into an array of parsed events. A truncated or corrupt final
// line (e.g. a crash mid-append) is skipped rather than thrown: the log is
// append-only, so the rest stays readable.
function auditReadLines(dir) {
  let raw;
  try { raw = fs.readFileSync(path.join(dir, 'audit.log'), 'utf8'); }
  catch (e) { return []; }  // no log yet
  const out = [];
  for (const line of raw.split('\n')) {
    if (!line) continue;
    try { out.push(JSON.parse(line)); } catch (e) { /* skip corrupt line */ }
  }
  return out;
}

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

// ══════════════════════════════════════════════════════════════
// PROOF PACKAGE EXPORT (item 2)
// ══════════════════════════════════════════════════════════════
// A downloadable, self-contained evidence bundle per letter: the exact bytes
// sent to Lob, Lob's creation response, the rendered PDF (what was physically
// printed), live tracking, correlated address verifications, and every audit
// line referencing the letter. Delivered as a store-only ZIP so the payload
// (mostly already-compressed PDF) is archived verbatim with a tiny, auditable
// writer. The writer is validated by an INDEPENDENT reader in the test suite,
// never only by itself.

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

// Buffered GET against an explicit target (single configured origin, never
// client-derived). Resolves (never rejects) so a fetch failure is data, not a
// thrown error that could sink an export.
function httpGetBuffer(target) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => { if (!settled) { settled = true; resolve(v); } };
    const req = target.transport.request({
      hostname: target.hostname, port: target.port, path: target.path, method: 'GET',
      headers: target.headers || {},
    }, (r) => {
      const parts = [];
      r.on('data', (c) => parts.push(c));
      r.on('end', () => done({ status: r.statusCode, buffer: Buffer.concat(parts), headers: r.headers }));
      r.on('error', (e) => done({ status: 0, buffer: Buffer.alloc(0), error: e.code || e.message }));
    });
    req.on('error', (e) => done({ status: 0, buffer: Buffer.alloc(0), error: e.code || e.message }));
    req.setTimeout(PROXY_TIMEOUT_MS, () => req.destroy(new Error('Upstream request timed out')));
    req.end();
  });
}

// Resolve a rendered-PDF URL to a fetch target. In stub/test mode
// (PD_LOB_UPSTREAM set) the URL is routed to the configured upstream by PATH,
// preserving the single-origin property the proxy already guarantees. In
// production only Lob-owned asset hosts are allowed, so a tampered url can
// never make the server fetch an arbitrary host. Returns null if disallowed.
function proxyTargetFor(urlString) {
  let u;
  try { u = new URL(urlString); } catch (e) { return null; }
  if ((process.env.PD_LOB_UPSTREAM || '').trim()) {
    return { hostname: LOB_UPSTREAM.hostname, port: LOB_UPSTREAM.port, transport: LOB_UPSTREAM.transport, path: u.pathname + u.search, headers: { host: LOB_UPSTREAM.hostname } };
  }
  const host = u.hostname.toLowerCase();
  const ok = host === 'lob.com' || host.endsWith('.lob.com') || host === 'lob-assets.com' || host.endsWith('.lob-assets.com');
  if (!ok) return null;
  const isHttp = u.protocol === 'http:';
  return { hostname: u.hostname, port: u.port ? parseInt(u.port, 10) : (isHttp ? 80 : 443), transport: isHttp ? http : https, path: u.pathname + u.search, headers: { host: u.hostname } };
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
  const lines = auditReadLines(dir);
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
    keyEnv: create ? (create.keyEnv || null) : null,
    idempotencyKey: create ? (create.idempotencyKey || null) : null,
    fingerprint: create ? (create.fingerprint || null) : null,
    recipient,
    options,
    files: inventory,
    fetched,
    missing,
    note: 'USPS does not confirm final delivery for ordinary First-Class mail. This package is the operator record of what was submitted to Lob and rendered for mailing.',
  };
  entries.push({ name: 'manifest.json', data: Buffer.from(JSON.stringify(manifest, null, 2)) });

  const zip = zipStore(entries);
  const packageSha256 = sha256Hex(zip);
  const exportEvent = { type: 'proof.export', letterId, packageSha256, fetched, missing: missing.map((m) => m.name) };
  auditAppend(dir, exportEvent, now);
  return { zip, manifest, packageSha256, missing, exportEvent };
}

// ══════════════════════════════════════════════════════════════
// REQUEST ROUTER
// ══════════════════════════════════════════════════════════════
async function route(req, res) {
  setSecurityHeaders(res); // every response: pages, static, proxy, redirects, errors
  // HSTS must only be sent over HTTPS per spec (browsers ignore it on plain
  // HTTP, and sending it there could poison local-dev setups), hence the
  // isSecure gate. Kept out of setSecurityHeaders on purpose: that function
  // deliberately takes no req, and its tests call it without one.
  if (isSecure(req)) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  // req.headers.host is attacker-controlled and unvalidated: an invalid
  // authority (spaces, a non-numeric port, an unclosed bracket) makes new URL
  // throw ERR_INVALID_URL. Left unguarded that throw crashes the whole process
  // (async handler -> unhandledRejection -> Node default exit), a trivial
  // unauthenticated DoS, so parse defensively and answer 400 on garbage.
  let url;
  try {
    url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  } catch (e) {
    if (!res.headersSent) sendJSON(res, 400, { error: { message: 'Bad request' } });
    return;
  }
  const pathname = url.pathname;
 
  // ── Login page ──
  if (pathname === '/login' && req.method === 'GET') {
    if (validateSession(getSessionToken(req))) return redirect(res, '/');
    return sendHTML(res, 200, loginPage(null));
  }
 
  // ── Login POST ──
  if (pathname === '/login' && req.method === 'POST') {
    const ip = clientIp(req);
    const secure = isSecure(req);
    const tooMany = () => {
      res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': String(Math.ceil(LOGIN_WINDOW_MS / 1000)) });
      res.end(loginPage('Too many failed attempts. Please wait a few minutes and try again.'));
    };
    const body = await readBody(req, res, LOGIN_BODY_LIMIT);
    if (body === null) return; // 413/400 already sent
    const params = new URLSearchParams(body.toString());
    const user = params.get('username') || '';
    const pass = params.get('password') || '';
    const userKey = bucketKey(user, BUCKET_KEY_MAX);

    // Credentials are evaluated BEFORE either bucket is consulted (both
    // comparisons are constant-time, so the ordering leaks nothing). The why:
    // the buckets exist to throttle GUESSING, not to deny service to whoever
    // holds the correct password. A correct login therefore always succeeds and
    // clears both buckets — critically including the per-IP bucket. Behind a
    // reverse proxy with PD_TRUST_PROXY off, every client collapses to the
    // proxy's socket IP, so gating a correct login on the IP bucket would let
    // any attacker's 5 failures lock out the real owner (and everyone else).
    // Only FAILED attempts consult and consume the buckets, below.
    const userOk = safeEqual(user, USERNAME);
    const passOk = safeEqual(pass, PASSWORD);
    if (userOk && passOk) {
      clearAttempts(ipAttempts, ip);
      clearAttempts(userAttempts, userKey);
      const token = createSession();
      setCookie(res, token, secure);
      return redirect(res, '/');
    }
    // Wrong credentials. If either bucket is already at the cap, reject without
    // recording further. Otherwise record in both, then 429 once either trips.
    if (attemptBlocked(ipAttempts, ip) || (userKey && attemptBlocked(userAttempts, userKey))) return tooMany();
    recordAttempt(ipAttempts, ip);
    if (userKey) recordAttempt(userAttempts, userKey);
    // Progressive delay + global throttle, decided from the just-recorded
    // consecutive-failure counts. Only evaluated failures reach this point,
    // so a correct password is never delayed or throttled.
    const ipRec = ipAttempts.get(ip);
    const userRec = userKey ? userAttempts.get(userKey) : null;
    const keyFailures = Math.max(ipRec ? ipRec.count : 1, userRec ? userRec.count : 1);
    const decision = loginThrottleDecision('fail', globalFailures, keyFailures, Date.now());
    globalFailures = decision.global;
    if (decision.action === 'throttle') return tooMany();
    if (decision.delayMs > 0) await loginFailureDelay.sleep(decision.delayMs);
    if (attemptBlocked(ipAttempts, ip) || (userKey && attemptBlocked(userAttempts, userKey))) return tooMany();
    return sendHTML(res, 401, loginPage('Invalid username or password'));
  }
 
  // ── Logout ──
  if (pathname === '/logout') {
    if (req.method !== 'POST') return redirect(res, '/'); // GET logout is a no-op (CSRF-safe)
    clearCookie(res, isSecure(req));
    return redirect(res, '/login');
  }
 
  // ── Everything below requires auth ──
  if (!validateSession(getSessionToken(req))) {
    return redirect(res, '/login');
  }
 
  // ── Frontend config (authenticated) ──
  if (pathname === '/api/config' && req.method === 'GET') {
    // server_key tells the UI a PD_LOB_KEY is configured; env is its
    // test/live mode. The key itself is never sent to the browser.
    return sendJSON(res, 200, { server_key: !!LOB_KEY, env: LOB_KEY_ENV });
  }

  // ── Prior sends for a fingerprint (authenticated): powers the duplicate
  // warning from the durable server record. ──
  if (pathname === '/api/sends' && req.method === 'GET') {
    const fp = url.searchParams.get('fingerprint') || '';
    if (!/^[0-9a-f]{64}$/.test(fp)) {
      return sendJSON(res, 400, { error: { message: 'Invalid fingerprint' } });
    }
    return sendJSON(res, 200, { sends: findSendsByFingerprint(auditReadLines(DATA_DIR), fp) });
  }

  // ── Proof package export (authenticated) ──
  if (pathname.startsWith('/api/proof/') && req.method === 'GET') {
    const letterId = pathname.slice('/api/proof/'.length);
    // Ground rule: a client-supplied id must pass strict format validation
    // BEFORE it is used in a query or path. Reject malformed ids up front.
    if (!LETTER_ID_RE.test(letterId)) {
      return sendJSON(res, 400, { error: { message: 'Invalid letter id' } });
    }
    // Fetch the letter object and its rendered PDF at export time. Auth follows
    // the same precedence as the proxy: the client's key, else the server key.
    const authHeader = lobAuthorization(req.headers['authorization']);
    const deps = {
      now: Date.now,
      fetchLetter: async (id) => {
        const headers = authHeader ? { host: LOB_UPSTREAM.hostname, authorization: authHeader } : { host: LOB_UPSTREAM.hostname };
        const r = await httpGetBuffer({ hostname: LOB_UPSTREAM.hostname, port: LOB_UPSTREAM.port, transport: LOB_UPSTREAM.transport, path: '/v1/letters/' + id, headers });
        if (r.status !== 200) return { ok: false, status: r.status, error: r.error };
        try { return { ok: true, letter: JSON.parse(r.buffer.toString('utf8')) }; }
        catch (e) { return { ok: false, status: r.status, error: 'unparseable letter object' }; }
      },
      fetchAsset: async (url) => {
        const t = proxyTargetFor(url);
        if (!t) return { ok: false, error: 'rendered PDF host not allowed' };
        const r = await httpGetBuffer(t);
        if (r.status !== 200) return { ok: false, status: r.status, error: r.error };
        return { ok: true, bytes: r.buffer };
      },
    };
    let pkg;
    try { pkg = await buildProofPackage(DATA_DIR, letterId, deps); }
    catch (e) {
      console.error('Proof export failed:', e);
      if (!res.headersSent) sendJSON(res, 500, { error: { message: 'Proof export failed' } });
      return;
    }
    const dateStr = new Date().toISOString().slice(0, 10);
    res.writeHead(200, {
      'Content-Type': 'application/zip',
      'Content-Disposition': 'attachment; filename="proof-' + letterId + '-' + dateStr + '.zip"',
      'Content-Length': String(pkg.zip.length),
    });
    return res.end(pkg.zip);
  }

  // ── Lob API proxy ──
  if (pathname.startsWith('/api/lob/')) {
    const lobPath = pathname.replace('/api/lob', '') + url.search;
    const bodyBuf = await readBody(req, res, PROXY_BODY_LIMIT);
    if (bodyBuf === null) return; // 413/400 already sent
 
    const options = {
      hostname: LOB_UPSTREAM.hostname,
      port: LOB_UPSTREAM.port,
      path: lobPath,
      method: req.method,
      headers: { ...req.headers, host: LOB_UPSTREAM.hostname },
    };
    delete options.headers['origin'];
    delete options.headers['referer'];
    delete options.headers['cookie'];
    delete options.headers['accept-encoding']; // prevent Lob from returning gzipped JSON we'd forward un-decoded
    // The proxy buffers the full body and writes it as one buffer, so Node
    // must compute framing from that buffer; forwarding the client's framing
    // headers can desynchronize them from the actual bytes written.
    delete options.headers['transfer-encoding'];
    delete options.headers['content-length'];
    // Inject the server-side Lob key (PD_LOB_KEY) unless the client sent its
    // own Authorization header — see lobAuthorization for the precedence.
    const lobAuth = lobAuthorization(options.headers['authorization']);
    if (lobAuth) options.headers['authorization'] = lobAuth;
    // Legally consequential calls are captured to the durable audit store. These
    // responses are small JSON, so for them we buffer the upstream response
    // fully (to record it and, for a create, the request bytes) before
    // answering the client. Everything else keeps streaming untouched.
    const auditType = proxyAuditType(req.method, lobPath);
    const upstreamAuth = options.headers['authorization'];

    const proxy = LOB_UPSTREAM.transport.request(options, (lobRes) => {
      // The client may have already disconnected while we waited on Lob; writing
      // to a destroyed response would throw from this async callback (outside the
      // route try/catch) and crash the process. Bail cleanly instead.
      if (res.destroyed) { lobRes.destroy(); return; }
      if (auditType) {
        // Buffer, capture (synchronously to disk), then forward the same bytes.
        const parts = [];
        lobRes.on('data', (c) => parts.push(c));
        lobRes.on('end', () => {
          const respBuf = Buffer.concat(parts);
          try {
            captureProxyEvent(DATA_DIR, auditType, lobPath, req.headers, upstreamAuth, bodyBuf, lobRes.statusCode, respBuf);
          } catch (e) {
            // A store failure must not sink a send that Lob already accepted, but
            // it is operationally serious, so log it loudly server-side.
            console.error('Audit capture failed for ' + auditType + ':', e && (e.code || e.message));
          }
          if (res.destroyed) return;
          res.writeHead(lobRes.statusCode, { 'Content-Type': lobRes.headers['content-type'] || 'application/json' });
          res.end(respBuf);
        });
        lobRes.on('error', (err) => {
          console.error('Lob proxy stream error:', err.code || err.message);
          if (!res.headersSent && !res.destroyed) {
            try { sendJSON(res, 502, { error: { message: 'Upstream request failed' } }); } catch (_) { /* ignore */ }
          } else { try { res.destroy(); } catch (_) { /* ignore */ } }
        });
        return;
      }
      res.writeHead(lobRes.statusCode, {
        'Content-Type': lobRes.headers['content-type'] || 'application/json',
      });
      // pipeline (not .pipe): an upstream mid-stream reset or a client abort is
      // delivered as a handled callback error and tears BOTH streams down,
      // rather than surfacing as an unhandled 'error' event that would crash the
      // single-process server. .pipe() forwards neither source errors nor
      // destination cleanup reliably across Node versions.
      pipeline(lobRes, res, (err) => {
        if (err) console.error('Lob proxy stream error:', err.code || err.message);
      });
    });

    // If the client goes away BEFORE the response finished (a mid-stream abort),
    // tear down the upstream request now instead of leaking its socket until the
    // timeout. On a normal completion writableFinished is true, so we leave the
    // request alone (and its socket free for keep-alive reuse).
    res.on('close', () => { if (!res.writableFinished) proxy.destroy(); });
    proxy.setTimeout(PROXY_TIMEOUT_MS, () => proxy.destroy(new Error('Upstream request timed out')));
    proxy.on('error', (e) => {
      // Log the real error server-side only: upstream error strings can leak
      // internals (addresses, TLS details) and are useless to the browser.
      console.error('Lob proxy error:', e);
      if (!res.headersSent) {
        sendJSON(res, 502, { error: { message: 'Upstream request failed' } });
      } else {
        res.destroy(); // response already streaming, just tear it down
      }
    });
    if (bodyBuf.length > 0) proxy.write(bodyBuf);
    proxy.end();
    return;
  }
 
  // ── Serve app ──
  if (pathname === '/' || pathname === '/index.html') {
    return serveStatic(res, 'index.html');
  }
 
  // ── Other static files ──
  serveStatic(res, pathname);
}

// Wrap every request in a catch-all so a throw anywhere in the router can never
// take down the single-process server: on an un-streamed response answer 500,
// otherwise tear the socket down. This is the per-request backstop; the
// process-level handlers below are the last resort for anything outside a request.
const server = http.createServer((req, res) => {
  Promise.resolve()
    .then(() => route(req, res))
    .catch((e) => {
      console.error('Unhandled request error:', e);
      if (!res.headersSent) {
        try { sendJSON(res, 500, { error: { message: 'Internal server error' } }); } catch (_) { /* ignore */ }
      } else {
        try { res.destroy(); } catch (_) { /* ignore */ }
      }
    });
});

// Slow-body / slowloris and connection-exhaustion resistance: Node's defaults
// (headers 60s, request 300s) are generous, so tighten them. requestTimeout is
// kept high enough to admit a large (up to 52 MB) upload over a slow link.
server.headersTimeout = 30 * 1000;      // headers must arrive within 30s
server.requestTimeout = 120 * 1000;     // whole request (incl. body) within 120s
server.keepAliveTimeout = 15 * 1000;    // idle keep-alive sockets close after 15s

// ══════════════════════════════════════════════════════════════
// STARTUP VALIDATION
// ══════════════════════════════════════════════════════════════
// Startup failures are fatal, request failures are not: the per-request
// catch-all above keeps a RUNNING server alive, but a server that cannot
// start must exit nonzero, or a supervisor sees a clean exit from a process
// that never bound its port. Pure function of an env object so tests cover
// every path without booting a process.
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

// Only bind the port when run directly (`node server.js`); requiring this module
// (e.g. from tests) must NOT start the server.
if (require.main === module) {
  const startup = validateStartupConfig(process.env);
  if (!startup.ok) {
    startup.errors.forEach((msg) => console.error('FATAL: ' + msg));
    if (startup.errors.some((msg) => msg.startsWith('PD_'))) {
      console.error('       (For a local demo only: PD_INSECURE_LOCAL_DEMO=1 skips the credential checks and binds 127.0.0.1.)');
    }
    process.exit(1);
  }
  // The audit store is the durable system of record: an unwritable data
  // directory is a fatal startup error, consistent with Phase 0's principle
  // that startup failures are fatal (a supervisor must not see success from a
  // server that cannot record what it sends). Demo mode persists too.
  const dataCheck = ensureDataDir(DATA_DIR);
  if (!dataCheck.ok) {
    console.error('FATAL: ' + dataCheck.error);
    process.exit(1);
  }
  // Last-resort safety net for anything that escapes the per-request try/catch
  // (timers, stream callbacks, native emitters). Log and keep serving rather
  // than let Node's default policy terminate the process. Installed only as the
  // entrypoint so importing the module in tests never swallows their failures.
  process.on('uncaughtException', (e) => console.error('uncaughtException:', e));
  process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e));
  // A listen failure (EADDRINUSE, EACCES) means the server is not running, and
  // without this handler it would be swallowed by the uncaughtException net
  // above and the process would idle out with exit code 0. Attached only as
  // the entrypoint so tests that listen on an ephemeral port keep node:test's
  // own failure reporting.
  server.on('error', (e) => {
    console.error('FATAL: could not listen on port ' + PORT + ': ' + (e.code || e.message));
    process.exit(1);
  });
  server.listen(PORT, startup.host, () => {
    console.log('');
    console.log('  PostDirect is running');
    console.log('');
    console.log(`     URL:      http://localhost:${PORT}`);
    console.log(`     Username: ${USERNAME}`);
    console.log(`     Password: ${'*'.repeat(PASSWORD.length)}`);
    if (LOB_KEY) console.log(`     Lob key:  server-configured (${LOB_KEY_ENV})`);
    console.log('');
    // The old soft warnings about default/weak credentials are gone: outside
    // demo mode those conditions are now fatal before listen, so the only
    // state worth warning about here is demo mode itself.
    if (startup.insecureDemo) {
      console.log('  WARNING: PD_INSECURE_LOCAL_DEMO=1: credential checks are OFF.');
      console.log('     Default/weak credentials are allowed. Bound to 127.0.0.1 ONLY.');
      console.log('     Never set this flag on a machine other people can reach.');
      if (!SECRET_FROM_ENV) {
        console.log('     Sessions use a random per-process secret and reset on every restart.');
      }
      console.log('');
    }
    if (LOB_KEY && !/^(test|live)_/.test(LOB_KEY)) {
      console.log('  WARNING: PD_LOB_KEY does not look like a Lob API key (expected');
      console.log('     it to start with test_ or live_). It will be treated as LIVE.');
      console.log('     Double-check the value.');
      console.log('');
    }
    console.log('  Press Ctrl+C to stop.');
    console.log('');
  });
}

// Exported for unit tests (node:test). Requiring this module does not start the
// server or bind a port (see the require.main guard above). Integration tests
// call server.listen(0) themselves on an ephemeral port.
module.exports = {
  server,
  signValue,
  createSession,
  validateSession,
  safeEqual,
  escapeHtml,
  lobAuthorization,
  lobKeyEnv,
  clientIp,
  ipBucket,
  bucketKey,
  attemptBlocked,
  recordAttempt,
  clearAttempts,
  loginThrottleDecision,
  loginFailureDelay,
  isSecure,
  parseCookies,
  setSecurityHeaders,
  validateStartupConfig,
  // Persistence / audit store (item 1)
  DATA_DIR,
  sha256Hex,
  normalizeAddressForHash,
  addressHash,
  ensureDataDir,
  auditAppend,
  blobStore,
  blobPath,
  readBlob,
  auditReadLines,
  auditQuery,
  findSendsByFingerprint,
  proxyAuditType,
  classifyProxyKeyEnv,
  captureProxyEvent,
  // Proof export (item 2)
  crc32,
  zipStore,
  proxyTargetFor,
  buildProofPackage,
};
