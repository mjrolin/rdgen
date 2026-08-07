import { Request, Response, NextFunction } from 'express';
import { PERMISSIONS, Role } from '../services/userStore';

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; username: string; name: string; role: Role };
    }
  }
}

export function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    const userPermissions = PERMISSIONS[req.user.role] || [];
    if (!userPermissions.includes(permission)) {
      return res.status(403).json({ success: false, error: 'Permission denied' });
    }
    next();
  };
}
