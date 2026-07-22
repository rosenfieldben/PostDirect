'use strict';
// PostDirect composition root: HTTP assembly, the request router, the login and
// app HTML pages, and the `node server.js` entrypoint. Everything else lives in
// flat lib/ modules, each inert on require (no bind, no I/O at module load):
//   • lib/config.js     env-derived constants + the pure startup validator
//   • lib/session.js    HMAC-signed stateless session cookies
//   • lib/ratelimit.js  in-memory login rate limiting + progressive delay
//   • lib/store.js      append-only audit log + content-addressed blob store
//   • lib/proof.js      per-letter evidence ZIP export
//   • lib/proxy.js      the single controlled path to the Lob upstream
// This file owns the genuinely HTTP-shaped pieces: the small response helpers,
// static file serving, the login page template, the router, and the server
// wiring. For backward compatibility with the existing unit tests (which
// require('./server')), every symbol the modules previously exported from this
// file is re-exported here unchanged (see module.exports at the bottom).
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const {
  PORT, USERNAME, PASSWORD, SECRET_FROM_ENV,
  LOB_KEY, lobKeyEnv, LOB_KEY_ENV, LOB_UPSTREAM,
  LOGIN_BODY_LIMIT, BUCKET_KEY_MAX, LOGIN_WINDOW_MS,
  validateStartupConfig,
} = require('./lib/config');

const {
  signValue, createSession, validateSession,
  parseCookies, getSessionToken, isSecure, setCookie, clearCookie, safeEqual,
} = require('./lib/session');

const {
  ipAttempts, userAttempts,
  clientIp, ipBucket, canonicalizeIp, bucketKey,
  attemptBlocked, recordAttempt, clearAttempts,
  loginThrottleDecision, loginFailureDelay,
} = require('./lib/ratelimit');

const {
  DATA_DIR, LETTER_ID_RE,
  sha256Hex, normalizeAddressForHash, addressHash,
  ensureDataDir, auditAppend, blobStore, blobPath, readBlob,
  auditReadLines, auditQuery, findSendsByFingerprint,
  proxyAuditType, classifyProxyKeyEnv, captureProxyEvent,
} = require('./lib/store');

const {
  crc32, zipStore, PROOF_FETCH_MAX_BYTES, httpGetBuffer, buildProofPackage,
} = require('./lib/proof');

const {
  lobAuthorization, proxyTargetFor, handleProxy,
} = require('./lib/proxy');

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
    // (and its awaiting handler) dangling. 'close' fires after 'end' as well,
    // but done() is idempotent so the normal path already resolved by then.
    req.on('close', () => done(null));
  });
}

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
// (writeHead merges with, and only overrides on name collision: none here).
// script-src is 'self' with NO 'unsafe-inline': all app JS is external ES
// modules under /js, and neither page carries an inline <script> or an on*=
// handler, so a reflected-XSS injection can no longer execute inline. style-src
// keeps 'unsafe-inline' deliberately: the login page is served pre-auth and its
// stylesheet cannot be an authenticated /css asset, and the app page still uses
// a few inline style="" attributes. Every origin in the policy is now 'self':
// the Source Serif 4 font is self-hosted under /fonts (font-src 'self'), so
// there are no third-party origins left (the earlier third-party font allowances
// on style-src and font-src are gone). font-src 'self' is stated explicitly rather
// than left to default-src so the policy reads as a complete inventory of what
// the browser may load. img-src keeps data: for the inline SVG data URIs in CSS.
const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";
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
const MIME_TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.mjs': 'application/javascript', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };

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
// LOGIN PAGE (Broadsheet: ink on paper, masthead rules, spot cyan)
// ══════════════════════════════════════════════════════════════
// Served PRE-AUTH, so it cannot link the authenticated /css assets; its styles
// are inline (style-src keeps 'unsafe-inline' for exactly this page). The
// tokens are copied from public/css/broadsheet.css; retune there first.
// The app's serif (Source Serif 4) is now a self-hosted static asset under
// /fonts, which sits BEHIND the auth gate. Carving a pre-auth hole in the gate
// for font files was considered and deliberately rejected, so this pre-auth
// page intentionally renders in the Georgia fallback stack, not the brand serif.
function loginPage(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PostDirect — Sign In</title>
<style>
  :root {
    --color-bg: #f3f2f2;
    --color-surface: #eae9e9;
    --color-text: #201e1d;
    --color-accent: #0088b0;
    --color-accent-600: #1186ac;
    --color-accent-700: #006786;
    --color-accent-2-700: #aa0b56;
    --color-neutral-400: #bab6b6;
    --color-divider: color-mix(in srgb, #201e1d 16%, transparent);
    --font-serif: Georgia, serif;
  }
  *, *::before, *::after { box-sizing: border-box; }
  body {
    margin: 0; background: var(--color-bg); color: var(--color-text);
    font-family: var(--font-serif); font-size: 15px; line-height: 1.55;
  }
  :focus { outline: none; }
  :focus-visible { outline: 2px solid var(--color-accent); outline-offset: 2px; }
  .sheet { max-width: 760px; margin: 0 auto; }
  .masthead-pad { padding: 28px 56px 0; }
  .masthead { border-top: 3px solid var(--color-text); }
  .masthead-row { display: flex; align-items: center; justify-content: space-between; padding: 13px 0; }
  .masthead-rule { border-bottom: 1px solid var(--color-text); }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-stamp {
    display: grid; place-items: center; width: 27px; height: 33px;
    border: 1px solid var(--color-text); background: var(--color-bg); flex-shrink: 0;
  }
  .brand-stamp-inner {
    display: grid; place-items: center; width: 21px; height: 27px;
    border: 1px dashed var(--color-neutral-400);
    font-weight: 600; font-size: 11px; color: var(--color-accent-700);
  }
  .brand-wordmark { font-weight: 600; font-size: 20px; letter-spacing: -0.015em; }
  .tagline {
    font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
    color: color-mix(in srgb, var(--color-text) 55%, transparent);
  }
  .content { padding: 64px 56px 80px; max-width: 460px; }
  h1 { margin: 0 0 10px; font-size: 42px; font-weight: 600; line-height: 1.12; letter-spacing: -0.015em; }
  .sub { margin: 0 0 40px; font-size: 15px; color: color-mix(in srgb, var(--color-text) 68%, transparent); }
  .error {
    margin: 0 0 26px; font-size: 13.5px; line-height: 1.6;
    color: var(--color-accent-2-700);
  }
  .field { margin-bottom: 22px; }
  .field.last { margin-bottom: 34px; }
  .field label {
    display: block; font-size: 12px; margin-bottom: 5px;
    color: color-mix(in srgb, var(--color-text) 70%, transparent);
  }
  .input {
    width: 100%; min-height: 36px; padding: 6px 10px; font: inherit; font-size: 14px;
    color: var(--color-text); caret-color: var(--color-accent);
    background: var(--color-surface);
    border: 1px solid var(--color-divider); border-radius: 2px;
  }
  .input:hover { border-color: color-mix(in srgb, var(--color-text) 45%, transparent); }
  .input:focus-visible { border-color: var(--color-accent); outline-offset: 0; }
  .btn {
    display: inline-flex; align-items: center; justify-content: center; width: 100%;
    margin-top: 10px; cursor: pointer; font-family: var(--font-serif); font-weight: 600;
    font-size: 14px; line-height: 1.2; color: var(--color-bg);
    background: var(--color-accent); border: 1px solid transparent;
    padding: 10px 18px; border-radius: 2px;
  }
  .btn:hover { background: var(--color-accent-600); }
  .btn:active { background: var(--color-accent-700); }
  .footer {
    margin: 30px 0 0; font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase;
    color: color-mix(in srgb, var(--color-text) 50%, transparent);
  }
</style>
</head>
<body>
<div class="sheet">
  <header class="masthead-pad">
    <div class="masthead">
      <div class="masthead-row">
        <div class="brand">
          <span class="brand-stamp" aria-hidden="true"><span class="brand-stamp-inner">PD</span></span>
          <span class="brand-wordmark">PostDirect</span>
        </div>
        <span class="tagline">Physical mail · USPS</span>
      </div>
      <div class="masthead-rule"></div>
    </div>
  </header>
  <div class="content">
    <h1>Sign in.</h1>
    <p class="sub">PostDirect mails real letters. Operators only.</p>
    ${error ? '<p class="error">' + escapeHtml(error) + '</p>' : ''}
    <form method="POST" action="/login">
      <div class="field">
        <label for="username">Username</label>
        <input class="input" type="text" name="username" id="username" autocomplete="username" required autofocus />
      </div>
      <div class="field last">
        <label for="password">Password</label>
        <input class="input" type="password" name="password" id="password" autocomplete="current-password" required />
      </div>
      <button class="btn" type="submit">Sign in</button>
    </form>
    <p class="footer">Secured access · sessions expire after 7 days</p>
  </div>
</div>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════════
// LOGIN THROTTLE STATE
// ══════════════════════════════════════════════════════════════
// Process-wide failed-attempt window for the global throttle. Kept here in the
// composition root (not in lib/ratelimit.js) because it is mutable request-path
// state owned by the login route: loginThrottleDecision is pure (state in, next
// state out) and the route threads this variable through it.
let globalFailures = { count: 0, first: 0 };

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
  // HEAD is served like GET so uptime/monitoring probes (and the generic HEAD a
  // client may send before a GET) get a 200, not a 302 into the auth gate. Node's
  // http server strips the body from a HEAD response on its own, so the same
  // sendHTML call is correct without any special-casing here.
  if (pathname === '/login' && (req.method === 'GET' || req.method === 'HEAD')) {
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
    // clears both buckets, critically including the per-IP bucket. Behind a
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
        const r = await httpGetBuffer(t, PROOF_FETCH_MAX_BYTES);
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
    // Completeness is advertised in headers so the client can warn the operator
    // that a bundle is partial WITHOUT unzipping it. The values are the same
    // ones in manifest.json (which remains authoritative). The missing list is
    // a fixed set of ASCII entry names, safe as a header value.
    res.writeHead(200, {
      'Content-Type': 'application/zip',
      'Content-Disposition': 'attachment; filename="proof-' + letterId + '-' + dateStr + '.zip"',
      'Content-Length': String(pkg.zip.length),
      'X-PD-Proof-Complete': pkg.manifest.complete ? 'true' : 'false',
      'X-PD-Proof-Has-Local-Record': pkg.manifest.hasLocalRecord ? 'true' : 'false',
      'X-PD-Proof-Missing': pkg.missing.map((m) => m.name).join(','),
    });
    return res.end(pkg.zip);
  }

  // ── Lob API proxy ──
  if (pathname.startsWith('/api/lob/')) {
    return handleProxy(req, res, pathname, url.search, { readBody, sendJSON });
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
// ENTRYPOINT
// ══════════════════════════════════════════════════════════════
// Only bind the port when run directly (`node server.js`); requiring this module
// (e.g. from tests) must NOT start the server. validateStartupConfig lives in
// lib/config.js (pure function of an env object); the fatal-on-failure policy is
// enforced here.
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

  // ── Graceful shutdown (SIGTERM/SIGINT) ──
  // Stop accepting new connections and let in-flight requests finish, so an
  // audited send that is mid-capture completes and the durable record is not
  // lost. The drain is BOUNDED at SHUTDOWN_DRAIN_MS because Phase 1 made
  // resubmits idempotent: any request we cut off can be safely retried by the
  // client (Lob de-dupes within its 24h window on the persisted Idempotency-Key),
  // so a forced termination never risks a duplicate letter. 25s sits just under
  // the 30s upstream timeout (PROXY_TIMEOUT_MS) and typical orchestrator kill
  // grace, so a single in-flight Lob round trip has a chance to finish before we
  // give up.
  const SHUTDOWN_DRAIN_MS = 25 * 1000;
  let shuttingDown = false;
  const gracefulShutdown = (signal) => {
    if (shuttingDown) {
      // A second signal means "stop waiting": force an immediate nonzero exit.
      console.error('FATAL: second ' + signal + ' during shutdown; forcing immediate exit.');
      process.exit(1);
    }
    shuttingDown = true;
    console.log('Received ' + signal + '; draining in-flight requests (up to ' + (SHUTDOWN_DRAIN_MS / 1000) + 's), no longer accepting new connections.');
    const timer = setTimeout(() => {
      server.getConnections((err, count) => {
        console.error('FATAL: drain timed out after ' + (SHUTDOWN_DRAIN_MS / 1000) + 's with ' +
          (err ? 'an unknown number of' : count) + ' connection(s) still open; exiting nonzero.');
        process.exit(1);
      });
    }, SHUTDOWN_DRAIN_MS);
    server.close(() => { clearTimeout(timer); console.log('Drained cleanly; exiting.'); process.exit(0); });
    // Close idle keep-alive sockets immediately so the drain waits only on ACTIVE
    // requests, not on connections sitting idle up to keepAliveTimeout.
    if (server.closeIdleConnections) server.closeIdleConnections();
  };
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}

// Exported for unit tests (node:test). Requiring this module does not start the
// server or bind a port (see the require.main guard above). Integration tests
// call server.listen(0) themselves on an ephemeral port. The split moved these
// symbols into lib/ modules; they are re-exported here UNCHANGED so existing
// test imports (require('./server')) keep working without churn.
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
  canonicalizeIp,
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
  // Persistence / audit store
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
  // Proof export
  crc32,
  zipStore,
  proxyTargetFor,
  buildProofPackage,
  httpGetBuffer,
  PROOF_FETCH_MAX_BYTES,
};
