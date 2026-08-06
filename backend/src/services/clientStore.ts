import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import logger from '../utils/logger';
import { encryptConfig, decryptConfig } from './cryptoService';

const CLIENTS_DIR = path.join(__dirname, '../../data/clients');

// ── Types ──────────────────────────────────────────────────────────────────────

interface ClientVersion {
  versionId: string;
  createdAt: string;
  label: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

interface ProfileEntry {
  profileId: string;
  name: string;
  host: string;
  platform: string;
  createdAt: string;
  updatedAt: string;
  latestVersionId: string;
  versions: ClientVersion[];
}

interface ClientData {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  profiles: ProfileEntry[];
}

export interface ClientListItem {
  id: string;
  name: string;
  profileCount: number;
  updatedAt: string;
}

export interface ProfileListItem {
  profileId: string;
  name: string;
  host: string;
  platform: string;
  versionCount: number;
  latestVersionId: string;
  updatedAt: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function clientFilePath(clientId: string): string {
  return path.join(CLIENTS_DIR, `${clientId}.json`);
}

function writeClientFile(clientId: string, data: ClientData): void {
  const filePath = clientFilePath(clientId);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  fs.chmodSync(filePath, 0o600);
}

function readClientFile(clientId: string): ClientData | undefined {
  const filePath = clientFilePath(clientId);
  if (!fs.existsSync(filePath)) {
    return undefined;
  }
  try {
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data) as ClientData;
  } catch (error) {
    logger.error(`Failed to read client file ${clientId}:`, error);
    return undefined;
  }
}

// ── Init ───────────────────────────────────────────────────────────────────────

export function initClientStore(): void {
  if (!fs.existsSync(CLIENTS_DIR)) {
    fs.mkdirSync(CLIENTS_DIR, { recursive: true, mode: 0o700 });
    logger.info(`Created clients directory at ${CLIENTS_DIR}`);
  }
}

// ── Client-level functions ─────────────────────────────────────────────────────

export function listClients(): ClientListItem[] {
  initClientStore();

  const files = fs.readdirSync(CLIENTS_DIR).filter((f) => f.endsWith('.json'));
  const clients: ClientListItem[] = [];

  for (const file of files) {
    try {
      const data = fs.readFileSync(path.join(CLIENTS_DIR, file), 'utf-8');
      const client = JSON.parse(data) as ClientData;
      clients.push({
        id: client.id,
        name: client.name,
        profileCount: client.profiles.length,
        updatedAt: client.updatedAt,
      });
    } catch (error) {
      logger.error(`Failed to read client file ${file}:`, error);
    }
  }

  clients.sort(
    (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
  );

  return clients;
}

export function getClient(id: string): ClientData | undefined {
  return readClientFile(id);
}

export function createClient(name: string): ClientData {
  initClientStore();

  const id = uuidv4();
  const now = new Date().toISOString();

  const client: ClientData = {
    id,
    name,
    createdAt: now,
    updatedAt: now,
    profiles: [],
  };

  writeClientFile(id, client);
  logger.info(`Created client ${id} (${name})`);

  return client;
}

export function renameClient(id: string, name: string): ClientData | undefined {
  const client = readClientFile(id);
  if (!client) {
    logger.warn(`Client ${id} not found for rename`);
    return undefined;
  }

  client.name = name;
  client.updatedAt = new Date().toISOString();
  writeClientFile(client.id, client);
  logger.info(`Renamed client ${id} to "${name}"`);
  return client;
}

export function deleteClient(id: string): boolean {
  const filePath = clientFilePath(id);
  if (!fs.existsSync(filePath)) {
    logger.warn(`Client ${id} not found for deletion`);
    return false;
  }

  fs.unlinkSync(filePath);
  logger.info(`Deleted client ${id}`);
  return true;
}

// ── Profile-level functions ────────────────────────────────────────────────────

export function createProfile(
  clientId: string,
  profileName: string,
  host: string,
  platform: string,
  config: Record<string, unknown>
): ProfileEntry | undefined {
  const client = readClientFile(clientId);
  if (!client) {
    logger.warn(`Client ${clientId} not found for createProfile`);
    return undefined;
  }

  const profileId = uuidv4();
  const versionId = uuidv4();
  const now = new Date().toISOString();

  const encrypted = encryptConfig(config);

  const profile: ProfileEntry = {
    profileId,
    name: profileName,
    host,
    platform,
    createdAt: now,
    updatedAt: now,
    latestVersionId: versionId,
    versions: [
      {
        versionId,
        createdAt: now,
        label: '',
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        ciphertext: encrypted.ciphertext,
      },
    ],
  };

  client.profiles.push(profile);
  client.updatedAt = now;
  writeClientFile(clientId, client);
  logger.info(`Created profile ${profileId} (${profileName}) for client ${clientId}`);

  return profile;
}

export function addProfileVersion(
  clientId: string,
  profileId: string,
  config: Record<string, unknown>
): ProfileEntry | undefined {
  const client = readClientFile(clientId);
  if (!client) {
    logger.warn(`Client ${clientId} not found for addProfileVersion`);
    return undefined;
  }

  const profile = client.profiles.find((p) => p.profileId === profileId);
  if (!profile) {
    logger.warn(`Profile ${profileId} not found in client ${clientId}`);
    return undefined;
  }

  const versionId = uuidv4();
  const now = new Date().toISOString();

  const encrypted = encryptConfig(config);

  profile.versions.push({
    versionId,
    createdAt: now,
    label: '',
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    ciphertext: encrypted.ciphertext,
  });
  profile.latestVersionId = versionId;
  profile.updatedAt = now;
  client.updatedAt = now;

  writeClientFile(clientId, client);
  logger.info(`Added version ${versionId} to profile ${profileId} in client ${clientId}`);

  return profile;
}

export function getProfileVersion(
  clientId: string,
  profileId: string,
  versionId: string
): Record<string, unknown> | undefined {
  const client = readClientFile(clientId);
  if (!client) {
    return undefined;
  }

  const profile = client.profiles.find((p) => p.profileId === profileId);
  if (!profile) {
    return undefined;
  }

  const version = profile.versions.find((v) => v.versionId === versionId);
  if (!version) {
    return undefined;
  }

  try {
    return decryptConfig(version.iv, version.authTag, version.ciphertext);
  } catch (error) {
    logger.error(`Failed to decrypt version ${versionId} in profile ${profileId}:`, error);
    return undefined;
  }
}

export function renameProfile(
  clientId: string,
  profileId: string,
  name: string
): ProfileEntry | undefined {
  const client = readClientFile(clientId);
  if (!client) {
    logger.warn(`Client ${clientId} not found for renameProfile`);
    return undefined;
  }

  const profile = client.profiles.find((p) => p.profileId === profileId);
  if (!profile) {
    logger.warn(`Profile ${profileId} not found in client ${clientId}`);
    return undefined;
  }

  profile.name = name;
  profile.updatedAt = new Date().toISOString();
  client.updatedAt = profile.updatedAt;
  writeClientFile(clientId, client);
  logger.info(`Renamed profile ${profileId} to "${name}" in client ${clientId}`);

  return profile;
}

export function deleteProfile(clientId: string, profileId: string): boolean {
  const client = readClientFile(clientId);
  if (!client) {
    logger.warn(`Client ${clientId} not found for deleteProfile`);
    return false;
  }

  const index = client.profiles.findIndex((p) => p.profileId === profileId);
  if (index === -1) {
    logger.warn(`Profile ${profileId} not found in client ${clientId}`);
    return false;
  }

  client.profiles.splice(index, 1);
  client.updatedAt = new Date().toISOString();
  writeClientFile(clientId, client);
  logger.info(`Deleted profile ${profileId} from client ${clientId}`);

  return true;
}

export function updateProfileHost(
  clientId: string,
  profileId: string,
  host: string
): ProfileEntry | undefined {
  const client = readClientFile(clientId);
  if (!client) {
    logger.warn(`Client ${clientId} not found for updateProfileHost`);
    return undefined;
  }

  const profile = client.profiles.find((p) => p.profileId === profileId);
  if (!profile) {
    logger.warn(`Profile ${profileId} not found in client ${clientId}`);
    return undefined;
  }

  profile.host = host;
  profile.updatedAt = new Date().toISOString();
  client.updatedAt = profile.updatedAt;
  writeClientFile(clientId, client);
  logger.info(`Updated host for profile ${profileId} in client ${clientId}`);

  return profile;
}
