'use strict';
// Stateless sessions: HMAC-signed cookies, no server-side store. The cookie
// value is `<issuedAt>.<signature>` where signature = HMAC-SHA256(PD_SECRET,
// issuedAt). Sessions survive restarts, but ONLY if PD_SECRET is stable across
// restarts (a random per-process fallback invalidates them). Stateless sessions
// cannot be revoked server-side; logout simply clears the cookie.
const crypto = require('crypto');
const { SESSION_SECRET, COOKIE_NAME, SESSION_MAX_AGE } = require('./config');

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

// Constant-time credential comparison (hash first so unequal lengths
// don't throw and length isn't leaked via early exit).
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

module.exports = {
  signValue, createSession, validateSession,
  parseCookies, getSessionToken, isSecure, setCookie, clearCookie, safeEqual,
};
