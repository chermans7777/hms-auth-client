"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authMiddleware = authMiddleware;
// Drop into an app's middleware.ts to gate routes:
//   import { authMiddleware } from '@hms/auth/middleware';
//   export const middleware = authMiddleware;
//   export const config = { matcher: ['/((?!_next|favicon.ico|api/auth).*)'] };
// Unauthenticated requests are redirected to the hub's /authorize, which returns to /api/auth/callback.
const server_1 = require("next/server");
const core_1 = require("./core");
const config_1 = require("./config");
async function authMiddleware(req) {
    const token = req.cookies.get(config_1.COOKIE)?.value;
    const session = token ? await (0, core_1.verifySessionCookie)(token) : null;
    if (session)
        return server_1.NextResponse.next();
    const auth = new URL('/authorize', config_1.AUTH_HUB_URL);
    auth.searchParams.set('app_id', config_1.APP_ID);
    auth.searchParams.set('redirect_uri', `${config_1.APP_URL}/api/auth/callback`);
    auth.searchParams.set('state', req.nextUrl.pathname + req.nextUrl.search);
    return server_1.NextResponse.redirect(auth);
}
