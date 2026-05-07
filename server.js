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
const SESSION_SECRET = process.env.PD_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME = 'pd_session';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days
 
// ══════════════════════════════════════════════════════════════
// SESSION STORE (in-memory, survives restarts via cookie re-validation)
// ══════════════════════════════════════════════════════════════
const sessions = new Map();
 
function createSession() {
  const id = crypto.randomBytes(32).toString('hex');
  const token = crypto.createHmac('sha256', SESSION_SECRET).update(id).digest('hex');
  sessions.set(token, { created: Date.now() });
  return token;
}
 
function validateSession(token) {
  if (!token) return false;
  const sess = sessions.get(token);
  if (!sess) return false;
  if (Date.now() - sess.created > SESSION_MAX_AGE) { sessions.delete(token); return false; }
  return true;
}
 
function destroySession(token) { sessions.delete(token); }
 
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(c => { const [k, ...v] = c.split('='); if (k) cookies[k.trim()] = v.join('=').trim(); });
  return cookies;
}
 
function getSessionToken(req) {
  return parseCookies(req.headers.cookie)[COOKIE_NAME] || null;
}
 
function setCookie(res, token) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE / 1000}`);
}
 
function clearCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}
 
// ══════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}
 
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
 
// ══════════════════════════════════════════════════════════════
// STATIC FILES
// ══════════════════════════════════════════════════════════════
const STATIC_DIR = path.join(__dirname, 'public');
const MIME_TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
 
function serveStatic(res, filePath) {
  const full = path.join(STATIC_DIR, filePath);
  if (!full.startsWith(STATIC_DIR)) { res.writeHead(403); res.end(); return; }
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
    --bg: #f4f1e8;
    --bg-grad: radial-gradient(1200px 600px at 50% -200px, #fbf8ef 0%, #f4f1e8 60%, #efebe0 100%);
    --surface: #ffffff;
    --surface-warm: #fbf8f0;
    --ink: #0c1a2e;
    --text: #1c2230;
    --text-dim: #5b6172;
    --text-muted: #9aa0ad;
    --border: #e6e1d2;
    --border-soft: #efebe0;
    --hairline: rgba(12, 26, 46, 0.08);
    --focus-ring: 0 0 0 3px rgba(12, 26, 46, 0.10);
    --accent: #0c1a2e;
    --accent-hover: #1a2840;
    --gold: #8a6d3a;
    --danger: #9a1f1f;
    --danger-bg: #fbf1f1;
    --white: #ffffff;
    --shadow-xs: 0 1px 1px rgba(12,26,46,0.04);
    --shadow-sm: 0 1px 2px rgba(12,26,46,0.05), 0 1px 1px rgba(12,26,46,0.03);
    --shadow-lg: 0 1px 2px rgba(12,26,46,0.04), 0 18px 40px rgba(12,26,46,0.08);
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
    padding: 48px 44px 36px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 16px;
    box-shadow: var(--shadow-lg);
    position: relative;
  }
  .login-card::before {
    content: "";
    position: absolute;
    inset: 0;
    border-radius: 16px;
    pointer-events: none;
    background: linear-gradient(180deg, rgba(255,255,255,0.6), transparent 30%);
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
    width: 38px; height: 38px;
    border-radius: 10px;
    background: linear-gradient(180deg, #142440 0%, #0c1a2e 100%);
    color: #f7efd9;
    display: inline-flex; align-items: center; justify-content: center;
    box-shadow: 0 1px 0 rgba(255,255,255,0.5) inset, 0 1px 2px rgba(12,26,46,0.18);
    position: relative;
  }
  .brand-mark-wrap::after {
    content: ""; position: absolute; right: -2px; top: -2px;
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--gold); box-shadow: 0 0 0 2px var(--surface);
  }
  .brand-mark { width: 20px; height: 20px; }
  .brand-name { font-family: 'Source Serif 4', Georgia, serif; font-weight: 600; font-size: 24px; color: var(--ink); letter-spacing: -0.02em; }
  .brand-sub {
    text-align: center;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 40px;
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
    padding: 11px 13px;
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 14px;
    font-family: 'Inter', sans-serif;
    background: var(--surface-warm);
    color: var(--text);
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s, background 0.15s;
    box-shadow: var(--shadow-xs);
  }
  .field-input:hover { border-color: #d2cdbc; }
  .field-input:focus { border-color: var(--ink); box-shadow: var(--focus-ring); background: var(--surface); }
  .btn {
    width: 100%;
    padding: 12px;
    border-radius: 7px;
    font-size: 13.5px;
    font-weight: 500;
    font-family: 'Inter', sans-serif;
    cursor: pointer;
    border: 1px solid transparent;
    background: linear-gradient(180deg, #1a2840 0%, #0c1a2e 100%);
    color: var(--white);
    transition: all 0.18s ease;
    margin-top: 14px;
    box-shadow: 0 1px 0 rgba(255,255,255,0.08) inset, 0 1px 2px rgba(12,26,46,0.18), 0 4px 12px rgba(12,26,46,0.10);
    letter-spacing: 0.01em;
  }
  .btn:hover {
    background: linear-gradient(180deg, #243454 0%, #14213a 100%);
    transform: translateY(-1px);
    box-shadow: 0 1px 0 rgba(255,255,255,0.10) inset, 0 2px 4px rgba(12,26,46,0.20), 0 8px 18px rgba(12,26,46,0.14);
  }
  .btn:active { transform: translateY(0); }
  .error {
    padding: 11px 14px;
    border-radius: 6px;
    background: var(--danger-bg);
    border: 1px solid rgba(154,31,31,0.2);
    color: var(--danger);
    font-size: 13px;
    margin-bottom: 20px;
    text-align: center;
  }
  .footer {
    text-align: center;
    margin-top: 30px;
    padding-top: 22px;
    border-top: 1px solid var(--border-soft);
    font-size: 10.5px;
    font-weight: 600;
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
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--success, #176b3b);
    box-shadow: 0 0 0 3px rgba(23,107,59,0.18);
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
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;
 
  // ── Login page ──
  if (pathname === '/login' && req.method === 'GET') {
    if (validateSession(getSessionToken(req))) return redirect(res, '/');
    return sendHTML(res, 200, loginPage(null));
  }
 
  // ── Login POST ──
  if (pathname === '/login' && req.method === 'POST') {
    const body = await readBody(req);
    const params = new URLSearchParams(body.toString());
    const user = params.get('username');
    const pass = params.get('password');
 
    if (user === USERNAME && pass === PASSWORD) {
      const token = createSession();
      setCookie(res, token);
      return redirect(res, '/');
    }
    return sendHTML(res, 401, loginPage('Invalid username or password'));
  }
 
  // ── Logout ──
  if (pathname === '/logout') {
    destroySession(getSessionToken(req));
    clearCookie(res);
    return redirect(res, '/login');
  }
 
  // ── Everything below requires auth ──
  if (!validateSession(getSessionToken(req))) {
    return redirect(res, '/login');
  }
 
  // ── Lob API proxy ──
  if (pathname.startsWith('/api/lob/')) {
    const lobPath = pathname.replace('/api/lob', '');
    const bodyBuf = await readBody(req);
 
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
 
    const proxy = https.request(options, (lobRes) => {
      res.writeHead(lobRes.statusCode, {
        'Content-Type': lobRes.headers['content-type'] || 'application/json',
      });
      lobRes.pipe(res);
    });
 
    proxy.on('error', (e) => sendJSON(res, 502, { error: { message: 'Proxy error: ' + e.message } }));
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
  console.log('  Press Ctrl+C to stop.');
  console.log('');
});
