// Safe to import anywhere (no next/headers). Framework wiring lives in the subpath exports:
//   '@hms/auth/middleware'  → authMiddleware
//   '@hms/auth/server'      → getSession, requireSession, callbackHandler, logoutHandler
export * from './config';
export * from './core';
