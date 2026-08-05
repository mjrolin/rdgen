import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';

const ORIGINAL_ENV = process.env.CLIENT_PROFILE_KEY;

const clientsDir = path.join(__dirname, '../../../data/clients');

const sampleConfig: Record<string, unknown> = {
  platform: 'windows',
  version: '1.4.9',
  configName: 'mrnery',
  appName: 'RustDesk',
  filename: 'mrnery',
  connectionDirection: 'Both',
  disableInstallation: false,
  disableSettings: false,
  host: 'rd01.suporte.net.br',
  key: 'abc123',
  apiServer: 'https://api.example.com',
  urlLink: '',
  downloadLink: '',
  companyName: 'Test Corp',
  approveMode: 'password-click',
  permanentPassword: 's3cret!',
  denyLanDiscovery: false,
  enableDirectIp: true,
  autoCloseInactivity: false,
  allowHideConnectionWindow: false,
  theme: 'system',
  themeMode: 'default',
  permissionsMode: 'default',
  permissionsType: 'full',
  enableKeyboard: true,
  enableClipboard: true,
  enableFileTransfer: true,
  enableAudio: true,
  enableTcp: true,
  enableRemoteRestart: true,
  enableRecording: true,
  enableBlockingInput: true,
  enableRemoteConfig: true,
  enablePrinter: false,
  enableCamera: true,
  enableTerminal: true,
  cycleMonitor: false,
  xOffline: false,
  removeNewVersionNotif: true,
  delayFix: false,
  showRecentTab: false,
  showFavoritesTab: false,
  showDiscoveredTab: false,
  showAddressBookTab: true,
  showMyGroupTab: true,
  removeWallpaper: false,
  defaultSettings: '',
  overrideSettings: '',
  customImageQuality: 50,
  codecPreference: 'vp9',
  enableHwCodec: true,
  fps: 30,
  displayMode: 'adaptive',
};

describe('clientStore', () => {
  before(() => {
    process.env.CLIENT_PROFILE_KEY = 'a'.repeat(64);
  });

  after(() => {
    if (ORIGINAL_ENV !== undefined) {
      process.env.CLIENT_PROFILE_KEY = ORIGINAL_ENV;
    } else {
      delete process.env.CLIENT_PROFILE_KEY;
    }
  });

  beforeEach(() => {
    // Clean up client JSON files between tests, keep the directory
    if (fs.existsSync(clientsDir)) {
      const files = fs.readdirSync(clientsDir);
      for (const file of files) {
        if (file.endsWith('.json')) {
          fs.unlinkSync(path.join(clientsDir, file));
        }
      }
    }
  });

  it('creates a client and lists it', async () => {
    const { initClientStore, createClient, listClients } = await import('../clientStore');
    initClientStore();

    const client = createClient('mrnery', 'rd01.suporte.net.br', sampleConfig);

    assert.ok(client.id, 'client should have an id');
    assert.strictEqual(client.name, 'mrnery');
    assert.strictEqual(client.host, 'rd01.suporte.net.br');
    assert.strictEqual(client.versions.length, 1);
    assert.ok(client.latestVersionId, 'client should have latestVersionId');

    const clients = listClients();
    assert.strictEqual(clients.length, 1);
    assert.strictEqual(clients[0].name, 'mrnery');
    assert.strictEqual(clients[0].versionCount, 1);
    assert.strictEqual(clients[0].host, 'rd01.suporte.net.br');
  });

  it('adds a new version without overwriting previous', async () => {
    const { initClientStore, createClient, addClientVersion, getClient } = await import('../clientStore');
    initClientStore();

    const client = createClient('mrnery', 'rd01.suporte.net.br', sampleConfig);
    const firstVersionId = client.latestVersionId;

    const modifiedConfig = { ...sampleConfig, permanentPassword: 'newpass' };
    const updated = addClientVersion(client.id, modifiedConfig);

    assert.ok(updated, 'updated client should exist');
    assert.strictEqual(updated!.versions.length, 2);
    assert.notStrictEqual(updated!.latestVersionId, firstVersionId, 'latestVersionId should change');

    // Both versions still accessible
    const fullClient = getClient(client.id);
    assert.strictEqual(fullClient!.versions.length, 2);
  });

  it('decrypts a specific version correctly', async () => {
    const { initClientStore, createClient, getClientVersion } = await import('../clientStore');
    initClientStore();

    const configWithPassword = { ...sampleConfig, permanentPassword: 'pass' };
    const client = createClient('testclient', 'rd01.test.com', configWithPassword);

    const decrypted = getClientVersion(client.id, client.latestVersionId);
    assert.ok(decrypted, 'decrypted config should exist');
    assert.strictEqual(decrypted!.permanentPassword, 'pass');
    assert.strictEqual(decrypted!.configName, 'mrnery');
  });

  it('deletes a client', async () => {
    const { initClientStore, createClient, deleteClient, listClients } = await import('../clientStore');
    initClientStore();

    const client = createClient('mrnery', 'rd01.suporte.net.br', sampleConfig);
    assert.strictEqual(listClients().length, 1);

    const deleted = deleteClient(client.id);
    assert.strictEqual(deleted, true);
    assert.strictEqual(listClients().length, 0);
  });

  it('returns undefined for non-existent client', async () => {
    const { initClientStore, getClient } = await import('../clientStore');
    initClientStore();

    const result = getClient('nonexistent');
    assert.strictEqual(result, undefined);
  });
});
