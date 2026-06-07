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
  const { payload } = await jwtVerify(token, JWKS, { issuer: AUTH_HUB_URL, audience: APP_ID });
  return { sub: String(payload.sub), email: String(payload.email), name: String(payload.name), role: String(payload.role), app: String(payload.app) };
}

const secret = () => new TextEncoder().encode(SESSION_SECRET);

/** Sign this app's own session cookie from a verified identity. */
export async function signSession(s: Session): Promise<string> {
  return new SignJWT({ email: s.email, name: s.name, role: s.role, app: s.app })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(s.sub)
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(secret());
}

/** Verify this app's session cookie. Returns null if missing/invalid/expired. */
export async function verifySessionCookie(token: string): Promise<Session | null> {
  try {
    const { payload } = await jwtVerify(token, secret());
    return { sub: String(payload.sub), email: String(payload.email), name: String(payload.name), role: String(payload.role), app: String(payload.app) };
  } catch {
    return null;
  }
}

export const isRole = (s: Session | null, role: string) => !!s && s.role === role;
