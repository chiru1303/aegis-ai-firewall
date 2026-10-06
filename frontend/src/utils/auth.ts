const AUTH_KEY = 'aegis_auth_session';
export interface AuthSession { user: string; role: string; tenant: string; expiresAt: number }
export function getAuthSession(): AuthSession | null {
  try { const value = JSON.parse(sessionStorage.getItem(AUTH_KEY) || 'null'); return value && value.expiresAt > Date.now() ? value : null; }
  catch { return null; }
}
export function isAuthenticated() { return getAuthSession() !== null; }
export async function login(username: string, password: string): Promise<void> {
  const response = await fetch('/api/v1/auth/login', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
  if (!response.ok) throw new Error('Sign in failed. Check your username and password.');
  const data = await response.json();
  sessionStorage.setItem(AUTH_KEY, JSON.stringify({ ...data, expiresAt: Date.now() + data.expires_in * 1000 }));
  localStorage.removeItem('aegis_api_key'); localStorage.removeItem(AUTH_KEY);
}
export async function logout() {
  sessionStorage.removeItem(AUTH_KEY);
  await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' });
}
