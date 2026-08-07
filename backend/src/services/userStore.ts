import fs from 'fs';
import path from 'path';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import logger from '../utils/logger';

const USERS_FILE = path.join(__dirname, '../../data/users.json');
const SALT_ROUNDS = 10;

export type Role = 'admin' | 'operador' | 'construtor' | 'visualizador';

export interface User {
  id: string;
  username: string;
  passwordHash: string;
  name: string;
  role: Role;
  isActive: boolean;
  createdAt: string;
  lastLogin?: string;
}

export type UserWithoutHash = Omit<User, 'passwordHash'>;

export const PERMISSIONS: Record<Role, string[]> = {
  admin: ['clients:read', 'clients:write', 'profiles:save', 'builds:generate', 'users:manage'],
  operador: ['clients:read', 'clients:write', 'profiles:save', 'builds:generate'],
  construtor: ['clients:read', 'builds:generate'],
  visualizador: ['clients:read'],
};

function loadUsers(): User[] {
  if (!fs.existsSync(USERS_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
  } catch {
    return [];
  }
}

function saveUsers(users: User[]): void {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  fs.chmodSync(USERS_FILE, 0o600);
}

export function initUserStore(): void {
  const dataDir = path.dirname(USERS_FILE);
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  }

  if (!fs.existsSync(USERS_FILE)) {
    const adminUser = process.env.ADMIN_USERNAME || 'admin';
    const adminPass = process.env.ADMIN_PASSWORD || 'rdgen@2024';
    const adminName = process.env.ADMIN_NAME || 'Administrador';

    const user: User = {
      id: uuidv4(),
      username: adminUser,
      passwordHash: bcrypt.hashSync(adminPass, SALT_ROUNDS),
      name: adminName,
      role: 'admin',
      isActive: true,
      createdAt: new Date().toISOString(),
    };

    saveUsers([user]);
    logger.info(`Created initial admin user: ${adminUser}`);
  }
}

export function getAllUsers(): UserWithoutHash[] {
  return loadUsers().map(({ passwordHash, ...rest }) => rest);
}

export function getUserByUsername(username: string): User | undefined {
  return loadUsers().find(u => u.username === username && u.isActive);
}

export function getUserById(id: string): User | undefined {
  return loadUsers().find(u => u.id === id);
}

export function createUser(username: string, password: string, name: string, role: Role): User {
  const users = loadUsers();
  if (users.find(u => u.username === username)) {
    throw new Error('Username already exists');
  }

  const user: User = {
    id: uuidv4(),
    username,
    passwordHash: bcrypt.hashSync(password, SALT_ROUNDS),
    name,
    role,
    isActive: true,
    createdAt: new Date().toISOString(),
  };

  users.push(user);
  saveUsers(users);
  logger.info(`Created user ${username} with role ${role}`);
  return user;
}

export function updateUser(id: string, updates: Partial<Pick<User, 'name' | 'role' | 'isActive' | 'passwordHash'>>): User | undefined {
  const users = loadUsers();
  const index = users.findIndex(u => u.id === id);
  if (index === -1) return undefined;

  users[index] = { ...users[index], ...updates };
  saveUsers(users);
  logger.info(`Updated user ${id}`);
  return users[index];
}

export function deleteUser(id: string): boolean {
  const users = loadUsers();
  const user = users.find(u => u.id === id);
  if (!user) return false;

  user.isActive = false;
  saveUsers(users);
  logger.info(`Deactivated user ${id}`);
  return true;
}

export function validatePassword(username: string, password: string): User | undefined {
  const user = getUserByUsername(username);
  if (!user || !user.isActive) return undefined;
  if (!bcrypt.compareSync(password, user.passwordHash)) return undefined;

  const users = loadUsers();
  const index = users.findIndex(u => u.id === user.id);
  if (index !== -1) {
    users[index].lastLogin = new Date().toISOString();
    saveUsers(users);
  }

  return user;
}

export function changePassword(id: string, newPassword: string): boolean {
  const users = loadUsers();
  const index = users.findIndex(u => u.id === id);
  if (index === -1) return false;

  users[index].passwordHash = bcrypt.hashSync(newPassword, SALT_ROUNDS);
  saveUsers(users);
  logger.info(`Changed password for user ${id}`);
  return true;
}
