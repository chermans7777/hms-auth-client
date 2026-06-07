import { NextResponse, type NextRequest } from 'next/server';
export declare function authMiddleware(req: NextRequest): Promise<NextResponse<unknown>>;
