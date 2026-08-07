import { getUser } from './auth';

export function hasPermission(permission: string): boolean {
  const user = getUser();
  if (!user) return false;
  return user.permissions?.includes(permission) ?? false;
}

export function canEdit(): boolean { return hasPermission('clients:write'); }
export function canSave(): boolean { return hasPermission('profiles:save'); }
export function canBuild(): boolean { return hasPermission('builds:generate'); }
export function isAdmin(): boolean { return hasPermission('users:manage'); }
