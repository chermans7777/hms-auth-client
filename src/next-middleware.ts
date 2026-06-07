// Drop into an app's middleware.ts to gate routes:
//   import { authMiddleware } from '@hms/auth/middleware';
//   export const middleware = authMiddleware;
//   export const config = { matcher: ['/((?!_next|favicon.ico|api/auth).*)'] };
// Unauthenticated requests are redirected to the hub's /authorize, which returns to /api/auth/callback.
import { NextResponse, type NextRequest } from 'next/server';
import { verifySessionCookie } from './core';
import { AUTH_HUB_URL, APP_ID, APP_URL, COOKIE } from './config';

export async function authMiddleware(req: NextRequest) {
  const token = req.cookies.get(COOKIE)?.value;
  const session = token ? await verifySessionCookie(token) : null;
  if (session) return NextResponse.next();

  const auth = new URL('/authorize', AUTH_HUB_URL);
  auth.searchParams.set('app_id', APP_ID);
  auth.searchParams.set('redirect_uri', `${APP_URL}/api/auth/callback`);
  auth.searchParams.set('state', req.nextUrl.pathname + req.nextUrl.search);
  return NextResponse.redirect(auth);
}
