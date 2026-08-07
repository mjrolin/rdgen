export interface UserData {
  id: string;
  username: string;
  name: string;
  role: string;
  permissions: string[];
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('rdgen_token');
}

export function getUser(): UserData | null {
  if (typeof window === 'undefined') return null;
  const data = localStorage.getItem('rdgen_user');
  if (!data) return null;
  try { return JSON.parse(data); } catch { return null; }
}

export function setAuth(token: string, user: UserData): void {
  localStorage.setItem('rdgen_token', token);
  localStorage.setItem('rdgen_user', JSON.stringify(user));
}

export function clearAuth(): void {
  localStorage.removeItem('rdgen_token');
  localStorage.removeItem('rdgen_user');
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

export async function checkAuth(): Promise<boolean> {
  const token = getToken();
  if (!token) return false;
  try {
    const res = await fetch('/api/auth/check', { headers: { 'X-Session-Token': token } });
    const data = await res.json();
    return data.success && data.data?.authenticated;
  } catch { return false; }
}

export async function logout(): Promise<void> {
  const token = getToken();
  if (token) {
    try {
      await fetch('/api/auth/logout', { method: 'POST', headers: { 'X-Session-Token': token } });
    } catch {}
  }
  clearAuth();
}
