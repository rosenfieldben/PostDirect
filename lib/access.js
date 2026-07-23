'use strict';
// Cloudflare Access origin enforcement. The perimeter terminates identity at the
// edge; this module lets PostDirect PROVE every request came through it, so the
// access layer can never be decorative. It validates the Cf-Access-Jwt-Assertion
// header (an RS256 JWT signed by the team's rotating keys) against the team's
// JWKS. Zero runtime dependencies: Node's crypto imports the JWK keys and
// verifies RS256, so no JWT library is pulled in. Nothing here runs at require
// (no network, no timers, no bind); the entrypoint primes the JWKS client
// explicitly, and every function takes its dependencies (the fetcher, the clock)
// by injection so tests mint their own keypair and never touch the network.
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { URL } = require('url');

// 60 seconds of clock skew tolerance either way on exp/nbf/iat: the edge and the
// origin are different machines, and a token that just expired or is about to
// become valid must not be rejected over sub-minute clock drift.
const SKEW_MS = 60 * 1000;
// Cloudflare rotates signing keys; refresh the whole JWKS on this cadence.
const JWKS_TTL_MS = 6 * 60 * 60 * 1000;
// An unknown-kid token may mean a rotation we have not fetched yet, but an
// attacker can also spray garbage kids. Floor on-demand refetches to at most one
// per this window so garbage-kid tokens cannot turn the origin into a JWKS-fetch
// amplifier against Cloudflare.
const JWKS_REFETCH_FLOOR_MS = 30 * 1000;
// A team domain is where key requests are sent, so a typo must die at boot rather
// than fetch keys from somewhere silly. Cloudflare team domains are exactly
// <team>.cloudflareaccess.com.
const TEAM_DOMAIN_RE = /^[a-z0-9-]+\.cloudflareaccess\.com$/;

// Resolve enforcement config from the environment. Both vars set turns the
// perimeter ON; both unset leaves every current behavior untouched; exactly one
// set is a descriptive error that server.js turns into a FATAL boot failure,
// because a half-configured perimeter is worse than none and must be loud, not
// latent.
function accessConfigFromEnv(env) {
  env = env || {};
  const teamDomain = String(env.PD_ACCESS_TEAM_DOMAIN == null ? '' : env.PD_ACCESS_TEAM_DOMAIN).trim();
  const aud = String(env.PD_ACCESS_AUD == null ? '' : env.PD_ACCESS_AUD).trim();
  if (!teamDomain && !aud) return { enabled: false };
  if (!teamDomain || !aud) {
    const present = teamDomain ? 'PD_ACCESS_TEAM_DOMAIN' : 'PD_ACCESS_AUD';
    const missing = teamDomain ? 'PD_ACCESS_AUD' : 'PD_ACCESS_TEAM_DOMAIN';
    return { error: 'Cloudflare Access is half-configured: ' + present + ' is set but ' + missing +
      ' is not. Set BOTH to enable the perimeter, or NEITHER to disable it.' };
  }
  if (!TEAM_DOMAIN_RE.test(teamDomain)) {
    return { error: 'PD_ACCESS_TEAM_DOMAIN must be a Cloudflare team domain like <team>.cloudflareaccess.com (got "' + teamDomain + '")' };
  }
  return { enabled: true, teamDomain, aud, issuer: 'https://' + teamDomain, certsUrl: 'https://' + teamDomain + '/cdn-cgi/access/certs' };
}

// Buffer of a base64url segment. Buffer's base64url decoding is lenient (it
// ignores stray characters), so a malformed segment decodes to bytes that the
// downstream JSON.parse / signature check rejects: still a reason, never a throw.
function b64urlToBuf(seg) { return Buffer.from(String(seg), 'base64url'); }

// The default JWKS fetcher: a bounded GET returning the parsed JWKS, or a
// rejected promise. Injected in tests. Bounds: a 5s timeout and a 1 MB ceiling,
// so a hung or hostile endpoint cannot stall or exhaust the origin. The scheme
// follows the URL so an operator/test seam (PD_ACCESS_CERTS_URL) can point this
// at a local http stub, exactly like PD_LOB_UPSTREAM does for the Lob proxy; the
// real team domain is always https.
function defaultFetchJwks(certsUrl) {
  const transport = (() => { try { return new URL(certsUrl).protocol === 'http:' ? http : https; } catch (e) { return https; } })();
  return new Promise((resolve, reject) => {
    const req = transport.get(certsUrl, { timeout: 5000 }, (res) => {
      if (res.statusCode !== 200) { res.resume(); reject(new Error('HTTP ' + res.statusCode)); return; }
      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        if (total > 1024 * 1024) { req.destroy(new Error('JWKS response exceeded 1 MB')); return; }
        chunks.push(c);
      });
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (e) { reject(new Error('unparseable JWKS')); }
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('JWKS fetch timed out')));
  });
}

// A JWKS client: holds the team's RSA public keys by kid and refreshes them.
// fetchJwks and the clock are injected. Fetch failures keep the previous cache
// if one exists (stale keys beat no keys; Cloudflare's rotation overlap keeps old
// keys valid for hours), and otherwise leave the client keyless (the per-request
// path fails closed, never the boot).
function createJwksClient(opts) {
  opts = opts || {};
  const certsUrl = opts.certsUrl;
  const fetchJwks = opts.fetchJwks || defaultFetchJwks;
  const floorMs = opts.floorMs == null ? JWKS_REFETCH_FLOOR_MS : opts.floorMs;
  const ttlMs = opts.ttlMs == null ? JWKS_TTL_MS : opts.ttlMs;
  let keys = new Map();       // kid -> crypto.KeyObject
  let lastAttemptMs = null;   // when the most recent fetch STARTED (null: never), for the floor
  let inflight = null;        // dedupe concurrent refetches into one network call

  function importJwks(jwks) {
    const next = new Map();
    const list = (jwks && Array.isArray(jwks.keys)) ? jwks.keys : [];
    for (const jwk of list) {
      if (!jwk || jwk.kty !== 'RSA' || typeof jwk.kid !== 'string' || !jwk.kid) continue;
      try { next.set(jwk.kid, crypto.createPublicKey({ key: jwk, format: 'jwk' })); }
      catch (e) { /* a single malformed key must not sink the whole set */ }
    }
    return next;
  }

  function fetchNow(nowMs) {
    lastAttemptMs = nowMs;
    inflight = Promise.resolve()
      .then(() => fetchJwks(certsUrl))
      .then((jwks) => {
        const next = importJwks(jwks);
        if (next.size) keys = next;
        else console.error('Access JWKS from ' + certsUrl + ' held no usable RSA keys; keeping ' + keys.size + ' cached key(s).');
      })
      .catch((e) => {
        console.error('Access JWKS fetch failed for ' + certsUrl + ': ' + (e && (e.code || e.message)) +
          (keys.size ? '; keeping ' + keys.size + ' cached key(s).' : '; no keys cached, enforced requests will 503.'));
      })
      .finally(() => { inflight = null; });
    return inflight;
  }

  return {
    getKey: (kid) => keys.get(kid) || null,
    hasKeys: () => keys.size > 0,
    keyCount: () => keys.size,
    lastAttemptMs: () => lastAttemptMs,
    // On-demand refresh, floored: at most one fetch per floorMs no matter how many
    // unknown-kid tokens arrive. Returns a promise that settles when the in-flight
    // (or just-started) fetch completes, or immediately when suppressed.
    refresh(nowMs) {
      if (inflight) return inflight;
      if (lastAttemptMs != null && (nowMs - lastAttemptMs) < floorMs) return Promise.resolve();
      return fetchNow(nowMs);
    },
    // Unfloored refresh, for startup priming and the scheduled TTL.
    forceRefresh(nowMs) {
      if (inflight) return inflight;
      return fetchNow(nowMs);
    },
    // Prime the cache at boot and keep it fresh: fetch now, then reschedule at the
    // TTL once healthy, or sooner with capped backoff while still keyless, so a
    // startup network hiccup self-heals without ever crash-looping the deployment.
    // Timers are unref'd so this never keeps the process alive on its own.
    start(nowFn) {
      const clock = nowFn || Date.now;
      let backoffMs = 1000;
      const BACKOFF_CAP_MS = 60 * 1000;
      const schedule = (ms) => { const t = setTimeout(tick, ms); if (t && t.unref) t.unref(); };
      const tick = () => {
        forceRefresh(clock()).then(() => {
          if (keys.size) { backoffMs = 1000; schedule(ttlMs); }
          else { const wait = backoffMs; backoffMs = Math.min(backoffMs * 2, BACKOFF_CAP_MS); schedule(wait); }
        });
      };
      tick();
    },
  };
}

// Verify one assertion against the cached keys and injected clock. Pure and
// TOTAL: any malformation is a returned reason, never a throw, because this runs
// on EVERY enforced request and must not feed the process catch-all. Returns
// { ok: true, email } or { ok: false, reason }. The reason is for the server log
// only; the client always sees a generic Forbidden.
function verifyAccessJwt(token, nowMs, deps) {
  deps = deps || {};
  const { getKey, issuer, aud } = deps;
  if (typeof token !== 'string' || token.length === 0) return { ok: false, reason: 'missing-token' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed-structure' };
  const [h64, p64, s64] = parts;

  let header;
  try { header = JSON.parse(b64urlToBuf(h64).toString('utf8')); }
  catch (e) { return { ok: false, reason: 'unparseable-header' }; }
  if (!header || typeof header !== 'object') return { ok: false, reason: 'unparseable-header' };
  // alg must be EXACTLY RS256. Rejecting anything else here defuses the JWT
  // alg-confusion classics before they can run: 'none' (accept-without-signature)
  // and 'HS256' (verify an attacker's HMAC using our public key as the shared
  // secret). We never reach an HMAC or a no-op verify path.
  if (header.alg !== 'RS256') return { ok: false, reason: 'bad-alg:' + header.alg };
  if (typeof header.kid !== 'string' || !header.kid) return { ok: false, reason: 'missing-kid' };
  const key = getKey(header.kid);
  // A distinct reason so the caller can trigger a floored refetch and retry once:
  // an unknown kid is the expected shape of a key rotation we have not seen yet.
  if (!key) return { ok: false, reason: 'unknown-kid' };

  // Verify the signature over the RAW header.payload bytes BEFORE trusting any
  // payload claim.
  const signingInput = Buffer.from(h64 + '.' + p64, 'ascii');
  let sigOk = false;
  try { sigOk = crypto.verify('RSA-SHA256', signingInput, key, b64urlToBuf(s64)); }
  catch (e) { sigOk = false; }
  if (!sigOk) return { ok: false, reason: 'bad-signature' };

  let payload;
  try { payload = JSON.parse(b64urlToBuf(p64).toString('utf8')); }
  catch (e) { return { ok: false, reason: 'unparseable-payload' }; }
  if (!payload || typeof payload !== 'object') return { ok: false, reason: 'unparseable-payload' };
  if (payload.iss !== issuer) return { ok: false, reason: 'bad-iss' };
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(aud)) return { ok: false, reason: 'bad-aud' };
  if (typeof payload.exp !== 'number') return { ok: false, reason: 'no-exp' };
  if (nowMs > payload.exp * 1000 + SKEW_MS) return { ok: false, reason: 'expired' };
  if (typeof payload.nbf === 'number' && nowMs < payload.nbf * 1000 - SKEW_MS) return { ok: false, reason: 'not-yet-valid' };
  if (typeof payload.iat === 'number' && nowMs < payload.iat * 1000 - SKEW_MS) return { ok: false, reason: 'issued-in-future' };
  return { ok: true, email: typeof payload.email === 'string' ? payload.email : null };
}

// Tie a config to a JWKS client. check() is the per-request entry point the
// server uses: verify against the cache; on an unknown kid, refetch (floored) and
// retry EXACTLY once, since a rotation is the benign explanation; then, if we
// still fail and hold no keys at all, flag noKeys so the caller answers 503 (our
// outage) rather than 403 (your token is bad).
function createEnforcer(config, client) {
  const enabled = !!(config && config.enabled);
  return {
    enabled,
    hasKeys: () => client.hasKeys(),
    async check(token, nowMs) {
      const deps = { getKey: client.getKey, issuer: config.issuer, aud: config.aud };
      let r = verifyAccessJwt(token, nowMs, deps);
      if (r.ok) return r;
      if (r.reason === 'unknown-kid') {
        await client.refresh(nowMs);
        r = verifyAccessJwt(token, nowMs, deps);
        if (r.ok) return r;
      }
      if (!client.hasKeys()) return { ok: false, reason: r.reason, noKeys: true };
      return r;
    },
  };
}

module.exports = {
  SKEW_MS, JWKS_TTL_MS, JWKS_REFETCH_FLOOR_MS, TEAM_DOMAIN_RE,
  accessConfigFromEnv, defaultFetchJwks, createJwksClient, verifyAccessJwt, createEnforcer,
};
