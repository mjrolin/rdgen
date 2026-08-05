import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import logger from '../utils/logger';
import { encryptConfig, decryptConfig } from './cryptoService';

const CLIENTS_DIR = path.join(__dirname, '../../data/clients');

interface ClientVersion {
  versionId: string;
  createdAt: string;
  label: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

interface ClientProfile {
  id: string;
  name: string;
  host: string;
  createdAt: string;
  updatedAt: string;
  latestVersionId: string;
  versions: ClientVersion[];
}

export interface ClientListItem {
  id: string;
  name: string;
  host: string;
  versionCount: number;
  latestVersionId: string;
  updatedAt: string;
}

export function initClientStore(): void {
  if (!fs.existsSync(CLIENTS_DIR)) {
    fs.mkdirSync(CLIENTS_DIR, { recursive: true, mode: 0o700 });
    logger.info(`Created clients directory at ${CLIENTS_DIR}`);
  }
}

function writeClientFile(clientId: string, data: ClientProfile): void {
  const filePath = path.join(CLIENTS_DIR, `${clientId}.json`);
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  fs.chmodSync(filePath, 0o600);
}

function readClientFile(clientId: string): ClientProfile | undefined {
  const filePath = path.join(CLIENTS_DIR, `${clientId}.json`);
  if (!fs.existsSync(filePath)) {
    return undefined;
  }
  try {
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data) as ClientProfile;
  } catch (error) {
    logger.error(`Failed to read client file ${clientId}:`, error);
    return undefined;
  }
}

export function listClients(): ClientListItem[] {
  initClientStore();

  const files = fs.readdirSync(CLIENTS_DIR).filter((f) => f.endsWith('.json'));
  const clients: ClientListItem[] = [];

  for (const file of files) {
    try {
      const data = fs.readFileSync(path.join(CLIENTS_DIR, file), 'utf-8');
      const profile = JSON.parse(data) as ClientProfile;
      clients.push({
        id: profile.id,
        name: profile.name,
        host: profile.host,
        versionCount: profile.versions.length,
        latestVersionId: profile.latestVersionId,
        updatedAt: profile.updatedAt,
      });
    } catch (error) {
      logger.error(`Failed to read client file ${file}:`, error);
    }
  }

  // Sort by updatedAt descending
  clients.sort(
    (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
  );

  return clients;
}

export function getClient(id: string): ClientProfile | undefined {
  return readClientFile(id);
}

export function getClientVersion(
  clientId: string,
  versionId: string
): Record<string, unknown> | undefined {
  const client = readClientFile(clientId);
  if (!client) {
    return undefined;
  }

  const version = client.versions.find((v) => v.versionId === versionId);
  if (!version) {
    return undefined;
  }

  try {
    return decryptConfig(version.iv, version.authTag, version.ciphertext);
  } catch (error) {
    logger.error(`Failed to decrypt version ${versionId} for client ${clientId}:`, error);
    return undefined;
  }
}

export function createClient(
  name: string,
  host: string,
  config: Record<string, unknown>
): ClientProfile {
  initClientStore();

  const id = uuidv4();
  const versionId = uuidv4();
  const now = new Date().toISOString();

  const encrypted = encryptConfig(config);

  const client: ClientProfile = {
    id,
    name,
    host,
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

  writeClientFile(id, client);
  logger.info(`Created client ${id} (${name})`);

  return client;
}

export function addClientVersion(
  id: string,
  config: Record<string, unknown>
): ClientProfile | undefined {
  const client = readClientFile(id);
  if (!client) {
    logger.warn(`Client ${id} not found for addClientVersion`);
    return undefined;
  }

  const versionId = uuidv4();
  const now = new Date().toISOString();

  const encrypted = encryptConfig(config);

  const newVersion: ClientVersion = {
    versionId,
    createdAt: now,
    label: '',
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    ciphertext: encrypted.ciphertext,
  };

  client.versions.push(newVersion);
  client.latestVersionId = versionId;
  client.updatedAt = now;

  // Update name/host if provided in config
  if (typeof config.configName === 'string' && config.configName) {
    client.name = config.configName;
  }
  if (typeof config.host === 'string' && config.host) {
    client.host = config.host;
  }

  writeClientFile(id, client);
  logger.info(`Added version ${versionId} to client ${id}`);

  return client;
}

export function deleteClient(id: string): boolean {
  const filePath = path.join(CLIENTS_DIR, `${id}.json`);
  if (!fs.existsSync(filePath)) {
    logger.warn(`Client ${id} not found for deletion`);
    return false;
  }

  fs.unlinkSync(filePath);
  logger.info(`Deleted client ${id}`);
  return true;
}
