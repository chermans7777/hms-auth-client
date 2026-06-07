import { NextResponse } from 'next/server';
import { type Session } from './core';
/** The signed-in user for this request, or null. Use in server components / route handlers. */
export declare function getSession(): Promise<Session | null>;
/** Require a session in a server context; returns the session or throws a redirect-to-hub URL string. */
export declare function requireSession(returnTo?: string): Promise<Session>;
/** GET /api/auth/callback — exchanges the hub code for a token and sets this app's session. */
export declare function callbackHandler(req: Request): Promise<NextResponse<unknown>>;
/** GET /api/auth/logout — clears the app session (and bounces through the hub to end SSO). */
export declare function logoutHandler(req: Request): Promise<NextResponse<unknown>>;
