import { cookies } from 'next/headers';
import { adminAuth, SESSION_COOKIE } from './firebase-admin';

export async function currentUser() {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  if (!token) return null;
  try { return await adminAuth.verifySessionCookie(token, true); } catch { return null; }
}
export async function requireUser() {
  const u = await currentUser();
  if (!u) throw new Error('UNAUTHENTICATED');
  return u;
}
