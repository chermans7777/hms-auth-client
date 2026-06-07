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
    const { payload } = await (0, jose_1.jwtVerify)(token, JWKS, { issuer: config_1.AUTH_HUB_URL, audience: config_1.APP_ID });
    return { sub: String(payload.sub), email: String(payload.email), name: String(payload.name), role: String(payload.role), app: String(payload.app) };
}
const secret = () => new TextEncoder().encode(config_1.SESSION_SECRET);
/** Sign this app's own session cookie from a verified identity. */
async function signSession(s) {
    return new jose_1.SignJWT({ email: s.email, name: s.name, role: s.role, app: s.app })
        .setProtectedHeader({ alg: 'HS256' })
        .setSubject(s.sub)
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(secret());
}
/** Verify this app's session cookie. Returns null if missing/invalid/expired. */
async function verifySessionCookie(token) {
    try {
        const { payload } = await (0, jose_1.jwtVerify)(token, secret());
        return { sub: String(payload.sub), email: String(payload.email), name: String(payload.name), role: String(payload.role), app: String(payload.app) };
    }
    catch {
        return null;
    }
}
const isRole = (s, role) => !!s && s.role === role;
exports.isRole = isRole;
