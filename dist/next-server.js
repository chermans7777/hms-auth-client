"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSession = getSession;
exports.requireSession = requireSession;
exports.callbackHandler = callbackHandler;
exports.logoutHandler = logoutHandler;
// Server-side helpers for App Router apps.
//   getSession()      — read the verified user in a server component / route handler (or null)
//   callbackHandler   — wire as GET of /api/auth/callback
//   logoutHandler     — wire as GET of /api/auth/logout
const headers_1 = require("next/headers");
const server_1 = require("next/server");
const core_1 = require("./core");
const config_1 = require("./config");
/** The signed-in user for this request, or null. Use in server components / route handlers. */
async function getSession() {
    const token = (await (0, headers_1.cookies)()).get(config_1.COOKIE)?.value;
    return token ? (0, core_1.verifySessionCookie)(token) : null;
}
/** Require a session in a server context; returns the session or throws a redirect-to-hub URL string. */
async function requireSession(returnTo = '/') {
    const s = await getSession();
    if (s)
        return s;
    const auth = new URL('/authorize', config_1.AUTH_HUB_URL);
    auth.searchParams.set('app_id', config_1.APP_ID);
    auth.searchParams.set('redirect_uri', `${config_1.APP_URL}/api/auth/callback`);
    auth.searchParams.set('state', returnTo);
    throw new Error(`HMS_AUTH_REDIRECT:${auth.toString()}`);
}
/** GET /api/auth/callback — exchanges the hub code for a token and sets this app's session. */
async function callbackHandler(req) {
    const url = new URL(req.url);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state') || '/';
    if (!code)
        return server_1.NextResponse.redirect(new URL('/', config_1.APP_URL));
    const res = await fetch(new URL('/api/token', config_1.AUTH_HUB_URL), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code, app_id: config_1.APP_ID }),
    });
    if (!res.ok)
        return new server_1.NextResponse('Sign-in failed', { status: 401 });
    const { token } = await res.json();
    const identity = await (0, core_1.verifyAccessToken)(token);
    const appSession = await (0, core_1.signSession)(identity);
    const dest = state.startsWith('/') ? new URL(state, config_1.APP_URL) : new URL('/', config_1.APP_URL);
    const response = server_1.NextResponse.redirect(dest);
    response.cookies.set(config_1.COOKIE, appSession, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 60 * 24 * 7,
    });
    return response;
}
/** GET /api/auth/logout — clears the app session (and bounces through the hub to end SSO). */
async function logoutHandler(req) {
    const url = new URL(req.url);
    const backToApp = url.searchParams.get('redirect') || '/';
    const hubLogout = new URL('/api/logout', config_1.AUTH_HUB_URL);
    hubLogout.searchParams.set('redirect', new URL(backToApp, config_1.APP_URL).toString());
    const response = server_1.NextResponse.redirect(hubLogout);
    response.cookies.delete(config_1.COOKIE);
    return response;
}
