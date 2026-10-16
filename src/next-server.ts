// Server-side helpers for App Router apps.
//   getSession()      — read the verified user in a server component / route handler (or null)
//   callbackHandler   — wire as GET of /api/auth/callback
//   logoutHandler     — wire as GET of /api/auth/logout
import { cookies } from 'next/headers';
import { NextResponse } from 'next/server';
import { verifyAccessToken, verifySessionCookie, signSession, type Session } from './core';
import { AUTH_HUB_URL, APP_ID, APP_URL, COOKIE } from './config';

/**
 * Resolve an untrusted return target to a SAFE same-origin URL under APP_URL. Rejects absolute URLs,
 * protocol-relative (`//evil.com`) and backslash (`/\evil.com`) tricks that `startsWith('/')` alone
 * lets through, so neither the SSO `state` nor the logout `redirect` can bounce a user off-site.
 */
function safeReturn(raw: string | null | undefined): URL {
  const base = new URL(APP_URL);
  if (raw && raw.startsWith('/') && !raw.startsWith('//') && !raw.startsWith('/\\')) {
    try {
      const candidate = new URL(raw, APP_URL);
      if (candidate.origin === base.origin) return candidate;
    } catch { /* fall through */ }
  }
  return new URL('/', APP_URL);
}

/** The signed-in user for this request, or null. Use in server components / route handlers. */
export async function getSession(): Promise<Session | null> {
  const token = (await cookies()).get(COOKIE)?.value;
  return token ? verifySessionCookie(token) : null;
}

/** Require a session in a server context; returns the session or throws a redirect-to-hub URL string. */
export async function requireSession(returnTo = '/'): Promise<Session> {
  const s = await getSession();
  if (s) return s;
  const auth = new URL('/authorize', AUTH_HUB_URL);
  auth.searchParams.set('app_id', APP_ID);
  auth.searchParams.set('redirect_uri', `${APP_URL}/api/auth/callback`);
  auth.searchParams.set('state', returnTo);
  throw new Error(`HMS_AUTH_REDIRECT:${auth.toString()}`);
}

/** GET /api/auth/callback — exchanges the hub code for a token and sets this app's session. */
export async function callbackHandler(req: Request) {
  const url = new URL(req.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state') || '/';
  if (!code) return NextResponse.redirect(new URL('/', APP_URL));

  const res = await fetch(new URL('/api/token', AUTH_HUB_URL), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code, app_id: APP_ID }),
  });
  if (!res.ok) return new NextResponse('Sign-in failed', { status: 401 });

  const { token } = await res.json();
  const identity = await verifyAccessToken(token);
  const appSession = await signSession(identity);

  const dest = safeReturn(state);
  const response = NextResponse.redirect(dest);
  response.cookies.set(COOKIE, appSession, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });
  return response;
}

/** GET /api/auth/logout — clears the app session (and bounces through the hub to end SSO). */
export async function logoutHandler(req: Request) {
  const url = new URL(req.url);
  const backToApp = safeReturn(url.searchParams.get('redirect')); // same-origin only; no off-site bounce
  const hubLogout = new URL('/api/logout', AUTH_HUB_URL);
  hubLogout.searchParams.set('redirect', backToApp.toString());
  const response = NextResponse.redirect(hubLogout);
  response.cookies.delete(COOKIE);
  return response;
}
