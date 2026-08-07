'use client';

import { useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { isAuthenticated, checkAuth, logout, getUser } from '@/lib/auth';

interface AuthGuardProps {
  children: React.ReactNode;
}

export default function AuthGuard({ children }: AuthGuardProps) {
  const [checking, setChecking] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const router = useRouter();
  const pathname = usePathname();

  // Public routes that don't need auth
  const publicRoutes = ['/login'];

  useEffect(() => {
    const verify = async () => {
      // Skip auth check for public routes
      if (publicRoutes.includes(pathname)) {
        setChecking(false);
        setAuthenticated(true);
        return;
      }

      // Check if we have a token
      if (!isAuthenticated()) {
        router.push('/login');
        return;
      }

      // Verify token with backend
      const valid = await checkAuth();
      if (!valid) {
        await logout();
        router.push('/login');
        return;
      }

      setAuthenticated(true);
      setChecking(false);
    };

    verify();
  }, [pathname, router]);

  if (checking) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white">Loading...</div>
      </div>
    );
  }

  if (!authenticated && !publicRoutes.includes(pathname)) {
    return null;
  }

  return <>{children}</>;
}

// Logout button component
export function LogoutButton() {
  const router = useRouter();
  const user = getUser();

  const handleLogout = async () => {
    await logout();
    router.push('/login');
  };

  return (
    <div className="flex items-center gap-4">
      {user && <span className="text-gray-400 text-sm">Logged in as: {user.name}</span>}
      <button
        onClick={handleLogout}
        className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
      >
        Logout
      </button>
    </div>
  );
}
