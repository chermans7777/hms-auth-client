# @hms/auth

Standard auth client for HMS apps. Single sign-on through the **HMS Auth Hub**: apps redirect
unauthenticated users to the hub, the hub signs them in once, and each app verifies the returned
RS256 token (via the hub's JWKS) and keeps its own session cookie. Works on a subdomain today and
keeps working after an app moves to its own domain (token-based, not a shared cookie).

## Install
```bash
npm i github:chermans7777/hms-auth-client
```

## Env (per app)
```
AUTH_HUB_URL=https://auth.hermansmechanical.com   # must equal the hub's issuer
APP_ID=riffsmith                                   # this app's id in the hub registry
APP_URL=https://riffsmith.hermansmechanical.com    # this app's own origin
APP_SESSION_SECRET=<random 32+ bytes>              # signs this app's session cookie
```

## Wire it (App Router)
**middleware.ts**
```ts
export { authMiddleware as middleware } from '@hms/auth/middleware';
export const config = { matcher: ['/((?!_next|favicon.ico|api/auth).*)'] };
```
**app/api/auth/callback/route.ts**
```ts
export { callbackHandler as GET } from '@hms/auth/server';
```
**app/api/auth/logout/route.ts**
```ts
export { logoutHandler as GET } from '@hms/auth/server';
```
**Read the user anywhere on the server**
```ts
import { getSession } from '@hms/auth/server';
const session = await getSession(); // { sub, email, name, role, app } | null
```

That's it — the middleware bounces guests to the hub, the callback sets the session, and
`getSession()` gives you the verified user. Use `session.role` for role checks.
