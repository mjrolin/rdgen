import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ApiKey } from '../types';
import logger from '../utils/logger';

const DATA_DIR = path.join(__dirname, '../../data');
const API_KEYS_FILE = path.join(DATA_DIR, 'apikeys.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initialize API keys file if it doesn't exist
if (!fs.existsSync(API_KEYS_FILE)) {
  fs.writeFileSync(API_KEYS_FILE, JSON.stringify([], null, 2));
}

function loadApiKeys(): ApiKey[] {
  try {
    const data = fs.readFileSync(API_KEYS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    logger.error('Error loading API keys:', error);
    return [];
  }
}

function saveApiKeys(keys: ApiKey[]): void {
  try {
    fs.writeFileSync(API_KEYS_FILE, JSON.stringify(keys, null, 2));
  } catch (error) {
    logger.error('Error saving API keys:', error);
  }
}

// Generate a secure API key
export function generateApiKey(): string {
  return `rdgen_${crypto.randomBytes(32).toString('hex')}`;
}

// Create a new API key
export function createApiKey(
  name: string,
  tenantId: string,
  options?: {
    rateLimit?: number;
    expiresAt?: string;
    defaultConfig?: Partial<ApiKey['defaultConfig']>;
  }
): ApiKey {
  const keys = loadApiKeys();

  const newKey: ApiKey = {
    id: crypto.randomUUID(),
    key: generateApiKey(),
    name,
    tenantId,
    isActive: true,
    createdAt: new Date().toISOString(),
    rateLimit: options?.rateLimit || 10, // Default 10 builds per day
    buildsToday: 0,
    lastResetDate: new Date().toISOString().split('T')[0],
    expiresAt: options?.expiresAt,
    defaultConfig: options?.defaultConfig,
  };

  keys.push(newKey);
  saveApiKeys(keys);

  logger.info(`Created API key for tenant: ${tenantId}`);
  return newKey;
}

// Get API key by key string
export function getApiKeyByKey(key: string): ApiKey | undefined {
  const keys = loadApiKeys();
  return keys.find(k => k.key === key);
}

// Get API key by ID
export function getApiKeyById(id: string): ApiKey | undefined {
  const keys = loadApiKeys();
  return keys.find(k => k.id === id);
}

// Get all API keys for a tenant
export function getApiKeysByTenant(tenantId: string): ApiKey[] {
  const keys = loadApiKeys();
  return keys.filter(k => k.tenantId === tenantId);
}

// Get all API keys (admin)
export function getAllApiKeys(): ApiKey[] {
  return loadApiKeys();
}

// Update API key
export function updateApiKey(id: string, updates: Partial<ApiKey>): ApiKey | undefined {
  const keys = loadApiKeys();
  const index = keys.findIndex(k => k.id === id);

  if (index === -1) return undefined;

  // Don't allow changing id or key
  delete updates.id;
  delete updates.key;

  keys[index] = { ...keys[index], ...updates };
  saveApiKeys(keys);

  return keys[index];
}

// Delete API key
export function deleteApiKey(id: string): boolean {
  const keys = loadApiKeys();
  const index = keys.findIndex(k => k.id === id);

  if (index === -1) return false;

  keys.splice(index, 1);
  saveApiKeys(keys);

  return true;
}

// Validate API key and check rate limit
export function validateApiKey(key: string): {
  valid: boolean;
  apiKey?: ApiKey;
  error?: string;
} {
  const apiKey = getApiKeyByKey(key);

  if (!apiKey) {
    return { valid: false, error: 'Invalid API key' };
  }

  if (!apiKey.isActive) {
    return { valid: false, error: 'API key is disabled' };
  }

  // Check expiration
  if (apiKey.expiresAt && new Date(apiKey.expiresAt) < new Date()) {
    return { valid: false, error: 'API key has expired' };
  }

  // Check and reset daily rate limit
  const today = new Date().toISOString().split('T')[0];
  if (apiKey.lastResetDate !== today) {
    // Reset daily counter
    updateApiKey(apiKey.id, {
      buildsToday: 0,
      lastResetDate: today,
    });
    apiKey.buildsToday = 0;
  }

  // Check rate limit
  if (apiKey.rateLimit && apiKey.buildsToday !== undefined && apiKey.buildsToday >= apiKey.rateLimit) {
    return { valid: false, error: `Rate limit exceeded (${apiKey.rateLimit} builds/day)` };
  }

  return { valid: true, apiKey };
}

// Increment build count for API key
export function incrementBuildCount(id: string): void {
  const apiKey = getApiKeyById(id);
  if (apiKey) {
    updateApiKey(id, {
      buildsToday: (apiKey.buildsToday || 0) + 1,
      lastUsedAt: new Date().toISOString(),
    });
  }
}

// Record API key usage
export function recordApiKeyUsage(id: string): void {
  updateApiKey(id, {
    lastUsedAt: new Date().toISOString(),
  });
}
