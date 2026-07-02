const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
 
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

// Production safety guard: refuse to START with the default/unset password.
// Gated on require.main so importing this module (e.g. unit tests) never exits;
// it only fires when run directly as the entrypoint (`node server.js`, including
// the Docker image which sets NODE_ENV=production). Dev keeps the soft warning
// printed by server.listen below.
if (require.main === module && process.env.NODE_ENV === 'production' && (!process.env.PD_PASSWORD || PASSWORD === 'changeme')) {
  console.error('FATAL: PD_PASSWORD is unset — refusing to start in production with the default password.');
  console.error('       Set PD_PASSWORD (and PD_USERNAME, PD_SECRET) before deploying.');
  process.exit(1);
}

// Request body size limits (bytes)
const LOGIN_BODY_LIMIT = 16 * 1024;          // 16 KB — the login form is tiny
const PROXY_BODY_LIMIT = 52 * 1024 * 1024;   // 52 MB — headroom over the 50 MB PDF cap + multipart overhead
const PROXY_TIMEOUT_MS = 30 * 1000;          // 30 s — upstream Lob request timeout

// Login rate limiting (per-IP, in-memory)
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;      // 15 minutes
const BUCKET_KEY_MAX = 256;                  // max chars of a username used as a bucket key
const ATTEMPT_MAP_MAX = 10000;               // max distinct keys per bucket between sweeps
 
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
  });
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
    if (xff) { const first = String(xff).split(',')[0].trim(); if (first) return first; }
  }
  return req.socket.remoteAddress || 'unknown';
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
  ${error ? '<div class="error">' + error + '</div>' : ''}
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
// REQUEST ROUTER
// ══════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  setSecurityHeaders(res); // every response: pages, static, proxy, redirects, errors
  // HSTS must only be sent over HTTPS per spec (browsers ignore it on plain
  // HTTP, and sending it there could poison local-dev setups), hence the
  // isSecure gate. Kept out of setSecurityHeaders on purpose: that function
  // deliberately takes no req, and its tests call it without one.
  if (isSecure(req)) res.setHeader('Strict-Transport-Security', 'max-age=15552000');
  const url = new URL(req.url, `http://${req.headers.host}`);
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
    // The per-IP check stays BEFORE the body read: cheap rejection of a
    // blocked source before allocating anything for the body.
    if (attemptBlocked(ipAttempts, ip)) return tooMany();
    const body = await readBody(req, res, LOGIN_BODY_LIMIT);
    if (body === null) return; // 413/400 already sent
    const params = new URLSearchParams(body.toString());
    const user = params.get('username') || '';
    const pass = params.get('password') || '';
    const userKey = bucketKey(user, BUCKET_KEY_MAX);

    // Credentials are evaluated BEFORE the username bucket is consulted (both
    // comparisons are constant-time, so the ordering leaks nothing). The why:
    // the username bucket exists to throttle guessing, not to lock out the
    // owner, so a correct password bypasses it entirely; otherwise 5 forged
    // failures against the known username would deny the real user service.
    const userOk = safeEqual(user, USERNAME);
    const passOk = safeEqual(pass, PASSWORD);
    if (userOk && passOk) {
      clearAttempts(ipAttempts, ip);
      clearAttempts(userAttempts, userKey);
      const token = createSession();
      setCookie(res, token, secure);
      return redirect(res, '/');
    }
    // Wrong credentials: record in both buckets, then 429 once either is at
    // the cap. Attacker-visible behavior is unchanged from the old ordering:
    // wrong passwords still hit the limit.
    recordAttempt(ipAttempts, ip);
    if (userKey) recordAttempt(userAttempts, userKey);
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
 
  // ── Lob API proxy ──
  if (pathname.startsWith('/api/lob/')) {
    const lobPath = pathname.replace('/api/lob', '') + url.search;
    const bodyBuf = await readBody(req, res, PROXY_BODY_LIMIT);
    if (bodyBuf === null) return; // 413/400 already sent
 
    const options = {
      hostname: 'api.lob.com',
      port: 443,
      path: lobPath,
      method: req.method,
      headers: { ...req.headers, host: 'api.lob.com' },
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
 
    const proxy = https.request(options, (lobRes) => {
      res.writeHead(lobRes.statusCode, {
        'Content-Type': lobRes.headers['content-type'] || 'application/json',
      });
      lobRes.pipe(res);
    });
 
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
});
 
// Only bind the port when run directly (`node server.js`); requiring this module
// (e.g. from tests) must NOT start the server.
if (require.main === module) {
  server.listen(PORT, () => {
    console.log('');
    console.log('  PostDirect is running');
    console.log('');
    console.log(`     URL:      http://localhost:${PORT}`);
    console.log(`     Username: ${USERNAME}`);
    console.log(`     Password: ${'*'.repeat(PASSWORD.length)}`);
    console.log('');
    if (PASSWORD === 'changeme') {
      console.log('  WARNING: Using default password!');
      console.log('     Set PD_USERNAME and PD_PASSWORD environment variables.');
      console.log('');
    }
    if (!SECRET_FROM_ENV) {
      console.log('  WARNING: PD_SECRET is not set — using a random per-process secret.');
      console.log('     Sessions will NOT survive restarts (every user is logged out on');
      console.log('     restart). Set PD_SECRET to a stable random string in production.');
      console.log('');
    }
    // Sessions are only as strong as the HMAC key: a short secret makes the
    // cookie signatures brute-forceable offline. (The random fallback above is
    // 64 hex chars, so this only fires for an explicitly set weak secret.)
    if (SECRET_FROM_ENV && SESSION_SECRET.length < 32) {
      console.log('  WARNING: PD_SECRET is shorter than 32 characters.');
      console.log('     Session cookies are HMAC-signed with it; a short secret can be');
      console.log('     brute-forced. Use at least 32 random characters, e.g.');
      console.log('     openssl rand -hex 32');
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
  clientIp,
  bucketKey,
  attemptBlocked,
  recordAttempt,
  clearAttempts,
  isSecure,
  parseCookies,
  setSecurityHeaders,
};
