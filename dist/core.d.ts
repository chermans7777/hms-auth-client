export interface Session {
    sub: string;
    email: string;
    name: string;
    role: 'admin' | 'employee' | 'customer' | 'consulting' | 'affiliate' | string;
    app: string;
}
/** Verify a hub-issued access token (RS256) against the hub's published public key. */
export declare function verifyAccessToken(token: string): Promise<Session>;
/** Sign this app's own session cookie from a verified identity. */
export declare function signSession(s: Session): Promise<string>;
/** Verify this app's session cookie. Returns null if missing/invalid/expired/weak-secret. */
export declare function verifySessionCookie(token: string): Promise<Session | null>;
export declare const isRole: (s: Session | null, role: string) => boolean;
