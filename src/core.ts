// Framework-agnostic token logic (jose). Verifies the hub's RS256 access token via JWKS, and
// signs/verifies this app's own HS256 session cookie (so the app session can outlive the 1h token).
import { createRemoteJWKSet, jwtVerify, SignJWT } from 'jose';
import { AUTH_HUB_URL, APP_ID, SESSION_SECRET } from './config';

const JWKS = createRemoteJWKSet(new URL('/.well-known/jwks.json', AUTH_HUB_URL));

export interface Session {
  sub: string;    // user id
  email: string;
  name: string;
  role: 'admin' | 'employee' | 'customer' | 'consulting' | 'affiliate' | string;
  app: string;    // app id this session belongs to
}

/** Verify a hub-issued access token (RS256) against the hub's published public key. */
export async function verifyAccessToken(token: string): Promise<Session> {
  // Pin algorithms: the JWKS only holds an RSA key, so only RS256 may verify. This keeps a future
  // key addition from re-opening alg-confusion.
  const { payload } = await jwtVerify(token, JWKS, { issuer: AUTH_HUB_URL, audience: APP_ID, algorithms: ['RS256'] });
  return { sub: String(payload.sub), email: String(payload.email), name: String(payload.name), role: String(payload.role), app: String(payload.app) };
}

// Fail CLOSED on a missing/weak session secret. A zero-length or short APP_SESSION_SECRET must never
// sign or accept a cookie — otherwise an unset env var silently makes `hms_session` forgeable (anyone
// could mint a role:"admin" cookie). We guard at call time (not module load) so an env-less `next build`
// doesn't break; at runtime, signing throws and verification rejects all cookies when the secret is weak.
const MIN_SECRET_LEN = 32;
const secretOk = () => typeof SESSION_SECRET === 'string' && SESSION_SECRET.length >= MIN_SECRET_LEN;
const secret = () => new TextEncoder().encode(SESSION_SECRET);

/** Sign this app's own session cookie from a verified identity. */
export async function signSession(s: Session): Promise<string> {
  if (!secretOk()) {
    throw new Error('APP_SESSION_SECRET is missing or shorter than 32 chars — refusing to sign a session cookie (set it in this app\'s env).');
  }
  return new SignJWT({ email: s.email, name: s.name, role: s.role, app: s.app })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(s.sub)
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(secret());
}

/** Verify this app's session cookie. Returns null if missing/invalid/expired/weak-secret. */
export async function verifySessionCookie(token: string): Promise<Session | null> {
  if (!secretOk()) return null; // fail closed: never trust a cookie when the key is weak/unset
  try {
    const { payload } = await jwtVerify(token, secret(), { algorithms: ['HS256'] });
    // Bind the cookie to this app: a session minted for a different app (same shared secret, if ever
    // misconfigured) must not be accepted here. Only enforced when APP_ID is configured.
    if (APP_ID && String(payload.app) !== APP_ID) return null;
    return { sub: String(payload.sub), email: String(payload.email), name: String(payload.name), role: String(payload.role), app: String(payload.app) };
  } catch {
    return null;
  }
}

export const isRole = (s: Session | null, role: string) => !!s && s.role === role;
