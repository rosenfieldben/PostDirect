'use strict';
// Item 1: the Cloudflare Access verifier. Tests mint their OWN RSA keypair,
// export the public side as a JWK with a kid, serve it from an injected fake
// fetcher, and sign tokens with crypto.sign, so the whole matrix runs with no
// network and no JWT library. The alg-confusion attacks are exercised directly.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const access = require('../lib/access.js');

const b64url = (x) => Buffer.from(x).toString('base64url');

// A keypair, its public JWK (with kid), and a token signer bound to it.
function makeKeypair(kid) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = kid;
  jwk.alg = 'RS256';
  jwk.use = 'sig';
  return { publicKey, privateKey, jwk, kid };
}

const ISSUER = 'https://team.cloudflareaccess.com';
const AUD = 'aud-1234567890';
const NOW = Date.parse('2026-07-23T12:00:00Z');
const validClaims = (over) => Object.assign(
  { iss: ISSUER, aud: AUD, exp: Math.floor(NOW / 1000) + 3600, iat: Math.floor(NOW / 1000) - 10, email: 'op@example.com' },
  over || {});

// Sign a token. alg drives which primitive signs it, so the confusion attacks can
// be minted: 'RS256' the real signature, 'HS256' an HMAC using the RSA public PEM
// as the shared secret, 'none' an empty signature.
function signToken(kp, claims, opts) {
  opts = opts || {};
  const alg = opts.alg || 'RS256';
  const header = b64url(JSON.stringify(Object.assign({ alg, kid: opts.kid || kp.kid, typ: 'JWT' }, opts.header || {})));
  const payload = b64url(JSON.stringify(claims));
  const signingInput = header + '.' + payload;
  let sig;
  if (alg === 'none') sig = Buffer.alloc(0);
  else if (alg === 'HS256') sig = crypto.createHmac('sha256', kp.publicKey.export({ format: 'pem', type: 'spki' })).update(signingInput).digest();
  else sig = crypto.sign('RSA-SHA256', Buffer.from(signingInput, 'ascii'), (opts.signWith || kp).privateKey);
  return signingInput + '.' + b64url(sig);
}

// A verifier bound to a static keyset (for the pure-verify matrix).
function depsFor(kps) {
  const keys = new Map(kps.map((kp) => [kp.kid, crypto.createPublicKey({ key: kp.jwk, format: 'jwk' })]));
  return { getKey: (kid) => keys.get(kid) || null, issuer: ISSUER, aud: AUD };
}

// ── accessConfigFromEnv ──
test('accessConfigFromEnv: both unset is disabled, both set is enabled, one set is an error', () => {
  assert.deepStrictEqual(access.accessConfigFromEnv({}), { enabled: false });
  const on = access.accessConfigFromEnv({ PD_ACCESS_TEAM_DOMAIN: 'acme.cloudflareaccess.com', PD_ACCESS_AUD: 'a1' });
  assert.strictEqual(on.enabled, true);
  assert.strictEqual(on.issuer, 'https://acme.cloudflareaccess.com');
  assert.strictEqual(on.certsUrl, 'https://acme.cloudflareaccess.com/cdn-cgi/access/certs');
  assert.match(access.accessConfigFromEnv({ PD_ACCESS_TEAM_DOMAIN: 'acme.cloudflareaccess.com' }).error, /half-configured/);
  assert.match(access.accessConfigFromEnv({ PD_ACCESS_AUD: 'a1' }).error, /half-configured/);
});

test('accessConfigFromEnv: a team domain that is not <team>.cloudflareaccess.com is a boot error', () => {
  assert.match(access.accessConfigFromEnv({ PD_ACCESS_TEAM_DOMAIN: 'evil.example.com', PD_ACCESS_AUD: 'a1' }).error, /team domain/);
  assert.match(access.accessConfigFromEnv({ PD_ACCESS_TEAM_DOMAIN: 'acme.cloudflareaccess.com.evil.com', PD_ACCESS_AUD: 'a1' }).error, /team domain/);
  assert.match(access.accessConfigFromEnv({ PD_ACCESS_TEAM_DOMAIN: 'UPPER.cloudflareaccess.com', PD_ACCESS_AUD: 'a1' }).error, /team domain/);
});

// ── verifyAccessJwt matrix ──
test('verifyAccessJwt: a valid token passes and returns the email claim', () => {
  const kp = makeKeypair('kid-A');
  const r = access.verifyAccessJwt(signToken(kp, validClaims()), NOW, depsFor([kp]));
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.email, 'op@example.com');
});

test('verifyAccessJwt: missing, garbage, and two-part tokens are rejected without throwing', () => {
  const deps = depsFor([makeKeypair('kid-A')]);
  for (const t of [undefined, null, '', 'not-a-jwt', 'only.two', 'a.b.c.d']) {
    const r = access.verifyAccessJwt(t, NOW, deps);
    assert.strictEqual(r.ok, false, JSON.stringify(t) + ' must be rejected');
    assert.ok(typeof r.reason === 'string' && r.reason.length > 0);
  }
});

test('verifyAccessJwt: alg=none is rejected (accept-without-signature)', () => {
  const kp = makeKeypair('kid-A');
  const r = access.verifyAccessJwt(signToken(kp, validClaims(), { alg: 'none' }), NOW, depsFor([kp]));
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /^bad-alg:none$/);
});

test('verifyAccessJwt: alg=HS256 forged with the public key as the HMAC secret is rejected (alg confusion)', () => {
  const kp = makeKeypair('kid-A');
  // The classic RS/HS confusion: an attacker who knows the public key signs an
  // HS256 token using that public key as the shared secret. A verifier that
  // trusted the token's alg would validate it. Ours rejects on alg before ever
  // reaching an HMAC path.
  const forged = signToken(kp, validClaims(), { alg: 'HS256' });
  const r = access.verifyAccessJwt(forged, NOW, depsFor([kp]));
  assert.strictEqual(r.ok, false);
  assert.match(r.reason, /^bad-alg:HS256$/);
});

test('verifyAccessJwt: an unknown kid reports the distinct unknown-kid reason', () => {
  const signer = makeKeypair('kid-real');
  const other = makeKeypair('kid-served');
  const r = access.verifyAccessJwt(signToken(signer, validClaims()), NOW, depsFor([other]));
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'unknown-kid');
});

test('verifyAccessJwt: a bad signature (payload tampered after signing) is rejected', () => {
  const kp = makeKeypair('kid-A');
  const token = signToken(kp, validClaims());
  const [h, , s] = token.split('.');
  const tampered = h + '.' + b64url(JSON.stringify(validClaims({ email: 'attacker@evil.com' }))) + '.' + s;
  const r = access.verifyAccessJwt(tampered, NOW, depsFor([kp]));
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.reason, 'bad-signature');
});

test('verifyAccessJwt: wrong iss and wrong aud are rejected; aud as an array containing the value passes', () => {
  const kp = makeKeypair('kid-A');
  const deps = depsFor([kp]);
  assert.strictEqual(access.verifyAccessJwt(signToken(kp, validClaims({ iss: 'https://evil.cloudflareaccess.com' })), NOW, deps).reason, 'bad-iss');
  assert.strictEqual(access.verifyAccessJwt(signToken(kp, validClaims({ aud: 'other-aud' })), NOW, deps).reason, 'bad-aud');
  const arr = access.verifyAccessJwt(signToken(kp, validClaims({ aud: ['x', AUD, 'y'] })), NOW, deps);
  assert.strictEqual(arr.ok, true, 'aud as an array containing the configured value passes');
});

test('verifyAccessJwt: exp/nbf/iat honor the 60-second skew window', () => {
  const kp = makeKeypair('kid-A');
  const deps = depsFor([kp]);
  const sec = Math.floor(NOW / 1000);
  // Expired 2 minutes ago: rejected. Expired 30s ago: within skew, accepted.
  assert.strictEqual(access.verifyAccessJwt(signToken(kp, validClaims({ exp: sec - 120 })), NOW, deps).reason, 'expired');
  assert.strictEqual(access.verifyAccessJwt(signToken(kp, validClaims({ exp: sec - 30 })), NOW, deps).ok, true);
  // A token missing exp entirely is rejected.
  assert.strictEqual(access.verifyAccessJwt(signToken(kp, validClaims({ exp: undefined })), NOW, deps).reason, 'no-exp');
  // nbf 2 minutes in the future: not yet valid. iat 2 minutes in the future: rejected.
  assert.strictEqual(access.verifyAccessJwt(signToken(kp, validClaims({ nbf: sec + 120 })), NOW, deps).reason, 'not-yet-valid');
  assert.strictEqual(access.verifyAccessJwt(signToken(kp, validClaims({ iat: sec + 120 })), NOW, deps).reason, 'issued-in-future');
  // nbf 30s in the future: within skew, accepted.
  assert.strictEqual(access.verifyAccessJwt(signToken(kp, validClaims({ nbf: sec + 30 })), NOW, deps).ok, true);
});

// ── JWKS client + enforcer ──
function jwksOf(kps) { return { keys: kps.map((kp) => kp.jwk) }; }

test('enforcer: an unknown kid triggers exactly one refetch, then the 30s floor suppresses a second', async () => {
  const served = makeKeypair('kid-served');
  const stranger = makeKeypair('kid-stranger');
  let fetches = 0;
  const client = access.createJwksClient({
    certsUrl: 'https://team.cloudflareaccess.com/cdn-cgi/access/certs',
    fetchJwks: async () => { fetches += 1; return jwksOf([served]); },
  });
  const enforcer = access.createEnforcer({ enabled: true, issuer: ISSUER, aud: AUD }, client);
  const tokenStranger = signToken(stranger, validClaims());

  // Times are NOW-relative so the token's own claims stay valid; the floor keys
  // off the delta between refetch attempts, not absolute time.
  const r1 = await enforcer.check(tokenStranger, NOW);
  assert.strictEqual(r1.ok, false);
  assert.strictEqual(r1.reason, 'unknown-kid');
  assert.strictEqual(fetches, 1, 'the first unknown kid triggered one refetch');

  const r2 = await enforcer.check(tokenStranger, NOW + 10_000); // 10s later, inside the floor
  assert.strictEqual(r2.ok, false);
  assert.strictEqual(fetches, 1, 'a second unknown kid within 30s did NOT refetch (floor)');

  // After the floor elapses, a fresh unknown kid refetches again.
  await enforcer.check(tokenStranger, NOW + 40_000);
  assert.strictEqual(fetches, 2, 'past the 30s floor, an unknown kid refetches once more');
});

test('enforcer: a refetch that now serves the rotated key lets the retry succeed', async () => {
  const rotated = makeKeypair('kid-rotated');
  let fetches = 0;
  const client = access.createJwksClient({
    certsUrl: 'https://team.cloudflareaccess.com/cdn-cgi/access/certs',
    // Keyless until the first fetch, which serves the rotated key.
    fetchJwks: async () => { fetches += 1; return jwksOf([rotated]); },
  });
  const enforcer = access.createEnforcer({ enabled: true, issuer: ISSUER, aud: AUD }, client);
  const r = await enforcer.check(signToken(rotated, validClaims()), NOW);
  assert.strictEqual(r.ok, true, 'the token verifies after the unknown-kid refetch pulled its key');
  assert.strictEqual(r.email, 'op@example.com');
  assert.strictEqual(fetches, 1);
});

test('enforcer: a keyless client (every fetch fails) reports noKeys so the caller can 503', async () => {
  const kp = makeKeypair('kid-A');
  const client = access.createJwksClient({
    certsUrl: 'https://team.cloudflareaccess.com/cdn-cgi/access/certs',
    fetchJwks: async () => { throw new Error('ENOTFOUND'); },
  });
  const enforcer = access.createEnforcer({ enabled: true, issuer: ISSUER, aud: AUD }, client);
  const realErr = console.error; console.error = () => {};
  let r;
  try { r = await enforcer.check(signToken(kp, validClaims()), NOW); } finally { console.error = realErr; }
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.noKeys, true, 'no keys at all is flagged distinctly from a bad token');
});

test('enforcer: a stale cache after a failed refresh still verifies a good token', async () => {
  const kp = makeKeypair('kid-A');
  let call = 0;
  const client = access.createJwksClient({
    certsUrl: 'https://team.cloudflareaccess.com/cdn-cgi/access/certs',
    fetchJwks: async () => { call += 1; if (call === 1) return jwksOf([kp]); throw new Error('EAI_AGAIN'); },
  });
  await client.forceRefresh(0);          // primes kid-A
  assert.strictEqual(client.hasKeys(), true);
  const realErr = console.error; console.error = () => {};
  try { await client.forceRefresh(1000); } finally { console.error = realErr; } // fails, keeps kid-A
  assert.strictEqual(client.hasKeys(), true, 'a failed refresh keeps the previous keys');
  const enforcer = access.createEnforcer({ enabled: true, issuer: ISSUER, aud: AUD }, client);
  const r = await enforcer.check(signToken(kp, validClaims()), NOW);
  assert.strictEqual(r.ok, true, 'stale-but-valid keys still verify');
});
