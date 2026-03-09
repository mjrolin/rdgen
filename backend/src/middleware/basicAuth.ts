import { Request, Response, NextFunction } from 'express';

// Users for basic auth (you can add more users here)
const USERS: Record<string, string> = {
  admin: process.env.PANEL_PASSWORD || 'rdgen@2024',
  'fernando.vargas': process.env.USER_FERNANDO_PASSWORD || 'FVargas@RDGen2026!Secure#',
};

// Endpoints that should be PUBLIC (GitHub Actions needs these, plus auth)
// These are matched against the full path (including /api prefix)
const PUBLIC_ENDPOINTS = [
  '/api/health',
  '/api/updategh',
  '/api/save_custom_client',
  '/api/get_png',
  '/api/auth/login',
  '/api/auth/logout',
  '/api/status/',    // Allow checking build status
  '/api/artifact/',  // Allow downloading artifacts
  '/api/token/',     // Token endpoints for RustDesk (MVP)
];

// Check if endpoint is public
function isPublicEndpoint(path: string): boolean {
  // Normalize path
  const normalizedPath = path.startsWith('/api') ? path : `/api${path}`;
  return PUBLIC_ENDPOINTS.some(endpoint => normalizedPath.startsWith(endpoint));
}

// Basic Auth middleware
export function basicAuth(req: Request, res: Response, next: NextFunction) {
  // Skip auth for public endpoints (GitHub Actions callbacks)
  if (isPublicEndpoint(req.path)) {
    return next();
  }

  // Skip auth if using API Key (for programmatic access)
  if (req.headers['x-api-key']) {
    return next();
  }

  // Skip auth if using Admin Secret
  if (req.headers['x-admin-secret']) {
    return next();
  }

  // Check for session token
  const sessionToken = req.headers['x-session-token'] as string;
  if (sessionToken && validateSessionToken(sessionToken)) {
    return next();
  }

  // No valid auth
  return res.status(401).json({
    success: false,
    error: 'Authentication required',
  });
}

// Session tokens storage (in production, use Redis or database)
const sessions: Map<string, { user: string; expires: number }> = new Map();

// Generate session token
export function createSession(user: string): string {
  const token = generateToken();
  const expires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  sessions.set(token, { user, expires });
  return token;
}

// Validate session token
function validateSessionToken(token: string): boolean {
  const session = sessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expires) {
    sessions.delete(token);
    return false;
  }
  return true;
}

// Delete session
export function deleteSession(token: string): void {
  sessions.delete(token);
}

// Validate user credentials
export function validateCredentials(username: string, password: string): boolean {
  const storedPassword = USERS[username];
  return storedPassword !== undefined && storedPassword === password;
}

// Generate random token
function generateToken(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';
  for (let i = 0; i < 64; i++) {
    token += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return token;
}
