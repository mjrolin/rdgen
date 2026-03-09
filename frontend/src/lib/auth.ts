// Auth utilities for frontend

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('rdgen_token');
}

export function getUser(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('rdgen_user');
}

export function setAuth(token: string, user: string): void {
  localStorage.setItem('rdgen_token', token);
  localStorage.setItem('rdgen_user', user);
}

export function clearAuth(): void {
  localStorage.removeItem('rdgen_token');
  localStorage.removeItem('rdgen_user');
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

export function getApiUrl(): string {
  // Use same origin - Next.js rewrites will proxy to backend
  return '';
}

export async function checkAuth(): Promise<boolean> {
  const token = getToken();
  if (!token) return false;

  try {
    const res = await fetch(`${getApiUrl()}/api/auth/check`, {
      headers: {
        'X-Session-Token': token,
      },
    });
    const data = await res.json();
    return data.success && data.authenticated;
  } catch {
    return false;
  }
}

export async function logout(): Promise<void> {
  const token = getToken();
  if (token) {
    try {
      await fetch(`${getApiUrl()}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'X-Session-Token': token,
        },
      });
    } catch {
      // Ignore errors on logout
    }
  }
  clearAuth();
}
