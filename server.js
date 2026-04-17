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
    --bg: #fcfcf9;
    --surface: #ffffff;
    --ink: #0f1419;
    --text: #1c1e24;
    --text-dim: #64666e;
    --text-muted: #9ca0a8;
    --border: #e8e5dc;
    --border-strong: #d1cec2;
    --focus: rgba(15, 20, 25, 0.08);
    --accent: #0f1419;
    --accent-hover: #2b2e36;
    --danger: #991b1b;
    --danger-bg: #fdf4f4;
    --white: #ffffff;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg);
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
    max-width: 400px;
    padding: 44px 40px 36px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 11px;
    margin-bottom: 10px;
    justify-content: center;
  }
  .brand-mark { width: 22px; height: 22px; color: var(--ink); }
  .brand-name { font-family: 'Source Serif 4', Georgia, serif; font-weight: 600; font-size: 22px; color: var(--ink); letter-spacing: -0.01em; }
  .brand-sub {
    text-align: center;
    font-size: 11.5px;
    font-weight: 500;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 36px;
  }
  .field { margin-bottom: 18px; }
  .field-label {
    display: block;
    margin-bottom: 7px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--text-dim);
  }
  .field-input {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--border);
    border-radius: 5px;
    font-size: 14px;
    font-family: 'Inter', sans-serif;
    background: var(--bg);
    color: var(--text);
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .field-input:focus { border-color: var(--ink); box-shadow: 0 0 0 3px var(--focus); }
  .btn {
    width: 100%;
    padding: 11px;
    border-radius: 6px;
    font-size: 13.5px;
    font-weight: 500;
    font-family: 'Inter', sans-serif;
    cursor: pointer;
    border: 1px solid transparent;
    background: var(--accent);
    color: var(--white);
    transition: background 0.15s;
    margin-top: 10px;
  }
  .btn:hover { background: var(--accent-hover); }
  .error {
    padding: 10px 14px;
    border-radius: 6px;
    background: var(--danger-bg);
    border: 1px solid rgba(153,27,27,0.2);
    color: var(--danger);
    font-size: 13px;
    margin-bottom: 20px;
    text-align: center;
  }
  .footer {
    text-align: center;
    margin-top: 26px;
    font-size: 11.5px;
    font-weight: 500;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text-muted);
  }
</style>
</head>
<body>
<div class="login-card">
  <div class="brand">
    <svg class="brand-mark" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <rect x="3" y="6" width="18" height="13" rx="1" stroke="currentColor" stroke-width="1.4"/>
      <path d="M3 8l9 6 9-6" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <div class="brand-name">PostDirect</div>
  </div>
  <div class="brand-sub">Sign in to continue</div>
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
