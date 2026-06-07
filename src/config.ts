// Per-app configuration, read from env. Set these in each app:
//   AUTH_HUB_URL        e.g. https://auth.hermansmechanical.com  (must match the hub's issuer)
//   APP_ID              this app's client id in the hub registry, e.g. "riffsmith"
//   APP_URL             this app's own origin, e.g. https://riffsmith.hermansmechanical.com
//   APP_SESSION_SECRET  random 32+ byte secret for signing this app's session cookie
export const AUTH_HUB_URL = process.env.AUTH_HUB_URL || 'http://localhost:3001';
export const APP_ID = process.env.APP_ID || '';
export const APP_URL = (process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');
export const SESSION_SECRET = process.env.APP_SESSION_SECRET || '';
export const COOKIE = 'hms_session';
