"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isRole = void 0;
exports.verifyAccessToken = verifyAccessToken;
exports.signSession = signSession;
exports.verifySessionCookie = verifySessionCookie;
// Framework-agnostic token logic (jose). Verifies the hub's RS256 access token via JWKS, and
// signs/verifies this app's own HS256 session cookie (so the app session can outlive the 1h token).
const jose_1 = require("jose");
const config_1 = require("./config");
const JWKS = (0, jose_1.createRemoteJWKSet)(new URL('/.well-known/jwks.json', config_1.AUTH_HUB_URL));
/** Verify a hub-issued access token (RS256) against the hub's published public key. */
async function verifyAccessToken(token) {
    // Pin algorithms: the JWKS only holds an RSA key, so only RS256 may verify. This keeps a future
    // key addition from re-opening alg-confusion.
    const { payload } = await (0, jose_1.jwtVerify)(token, JWKS, { issuer: config_1.AUTH_HUB_URL, audience: config_1.APP_ID, algorithms: ['RS256'] });
    return { sub: String(payload.sub), email: String(payload.email), name: String(payload.name), role: String(payload.role), app: String(payload.app) };
}
// Fail CLOSED on a missing/weak session secret. A zero-length or short APP_SESSION_SECRET must never
// sign or accept a cookie — otherwise an unset env var silently makes `hms_session` forgeable (anyone
// could mint a role:"admin" cookie). We guard at call time (not module load) so an env-less `next build`
// doesn't break; at runtime, signing throws and verification rejects all cookies when the secret is weak.
const MIN_SECRET_LEN = 32;
const secretOk = () => typeof config_1.SESSION_SECRET === 'string' && config_1.SESSION_SECRET.length >= MIN_SECRET_LEN;
const secret = () => new TextEncoder().encode(config_1.SESSION_SECRET);
/** Sign this app's own session cookie from a verified identity. */
async function signSession(s) {
    if (!secretOk()) {
        throw new Error('APP_SESSION_SECRET is missing or shorter than 32 chars — refusing to sign a session cookie (set it in this app\'s env).');
    }
    return new jose_1.SignJWT({ email: s.email, name: s.name, role: s.role, app: s.app })
        .setProtectedHeader({ alg: 'HS256' })
        .setSubject(s.sub)
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(secret());
}
/** Verify this app's session cookie. Returns null if missing/invalid/expired/weak-secret. */
async function verifySessionCookie(token) {
    if (!secretOk())
        return null; // fail closed: never trust a cookie when the key is weak/unset
    try {
        const { payload } = await (0, jose_1.jwtVerify)(token, secret(), { algorithms: ['HS256'] });
        // Bind the cookie to this app: a session minted for a different app (same shared secret, if ever
        // misconfigured) must not be accepted here. Only enforced when APP_ID is configured.
        if (config_1.APP_ID && String(payload.app) !== config_1.APP_ID)
            return null;
        return { sub: String(payload.sub), email: String(payload.email), name: String(payload.name), role: String(payload.role), app: String(payload.app) };
    }
    catch {
        return null;
    }
}
const isRole = (s, role) => !!s && s.role === role;
exports.isRole = isRole;
