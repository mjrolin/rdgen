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

describe('clientStore (multi-profile model)', () => {
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
    if (fs.existsSync(clientsDir)) {
      const files = fs.readdirSync(clientsDir);
      for (const file of files) {
        if (file.endsWith('.json')) {
          fs.unlinkSync(path.join(clientsDir, file));
        }
      }
    }
  });

  it('creates a client with empty profiles and lists it', async () => {
    const { initClientStore, createClient, listClients } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');

    assert.ok(client.id, 'client should have an id');
    assert.strictEqual(client.name, 'NextCoreTI');
    assert.ok(Array.isArray(client.profiles), 'client should have a profiles array');
    assert.strictEqual(client.profiles.length, 0);

    const clients = listClients();
    assert.strictEqual(clients.length, 1);
    assert.strictEqual(clients[0].name, 'NextCoreTI');
    assert.strictEqual(clients[0].profileCount, 0);
  });

  it('creates a profile under a client', async () => {
    const { initClientStore, createClient, createProfile, getClient } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
    const profile = createProfile(client.id, 'Admin', 'rd01.suporte.net.br', 'windows', sampleConfig);

    assert.ok(profile, 'profile should be created');
    assert.ok(profile!.profileId, 'profile should have a profileId');
    assert.strictEqual(profile!.name, 'Admin');
    assert.strictEqual(profile!.host, 'rd01.suporte.net.br');
    assert.strictEqual(profile!.platform, 'windows');
    assert.strictEqual(profile!.versions.length, 1);
    assert.ok(profile!.latestVersionId);

    const fullClient = getClient(client.id);
    assert.strictEqual(fullClient!.profiles.length, 1);
    assert.strictEqual(fullClient!.profiles[0].profileId, profile!.profileId);
  });

  it('adds a new version to a profile', async () => {
    const { initClientStore, createClient, createProfile, addProfileVersion, getClient } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
    const profile = createProfile(client.id, 'Admin', 'rd01.suporte.net.br', 'windows', sampleConfig);
    const firstVersionId = profile!.latestVersionId;

    const modifiedConfig = { ...sampleConfig, permanentPassword: 'newpass' };
    const updated = addProfileVersion(client.id, profile!.profileId, modifiedConfig);

    assert.ok(updated, 'updated profile should exist');
    assert.strictEqual(updated!.versions.length, 2);
    assert.notStrictEqual(updated!.latestVersionId, firstVersionId, 'latestVersionId should change');

    const fullClient = getClient(client.id);
    assert.strictEqual(fullClient!.profiles[0].versions.length, 2);
  });

  it('decrypts a specific profile version correctly', async () => {
    const { initClientStore, createClient, createProfile, getProfileVersion } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
    const profile = createProfile(client.id, 'Admin', 'rd01.suporte.net.br', 'windows', sampleConfig);

    const decrypted = getProfileVersion(client.id, profile!.profileId, profile!.latestVersionId);
    assert.ok(decrypted, 'decrypted config should exist');
    assert.strictEqual(decrypted!.permanentPassword, 's3cret!');
    assert.strictEqual(decrypted!.configName, 'mrnery');
  });

  it('renames a profile', async () => {
    const { initClientStore, createClient, createProfile, renameProfile } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
    const profile = createProfile(client.id, 'Admin', 'rd01.suporte.net.br', 'windows', sampleConfig);

    const renamed = renameProfile(client.id, profile!.profileId, 'PowerUser');
    assert.ok(renamed);
    assert.strictEqual(renamed!.name, 'PowerUser');
  });

  it('updates profile host', async () => {
    const { initClientStore, createClient, createProfile, updateProfileHost } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
    const profile = createProfile(client.id, 'Admin', 'rd01.suporte.net.br', 'windows', sampleConfig);

    const updated = updateProfileHost(client.id, profile!.profileId, 'rd02.suporte.net.br');
    assert.ok(updated);
    assert.strictEqual(updated!.host, 'rd02.suporte.net.br');
  });

  it('deletes a profile', async () => {
    const { initClientStore, createClient, createProfile, deleteProfile, getClient } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
    const profile = createProfile(client.id, 'Admin', 'rd01.suporte.net.br', 'windows', sampleConfig);
    assert.strictEqual(getClient(client.id)!.profiles.length, 1);

    const deleted = deleteProfile(client.id, profile!.profileId);
    assert.strictEqual(deleted, true);
    assert.strictEqual(getClient(client.id)!.profiles.length, 0);
  });

  it('renames a client', async () => {
    const { initClientStore, createClient, renameClient } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
    const renamed = renameClient(client.id, 'NewName');
    assert.ok(renamed);
    assert.strictEqual(renamed!.name, 'NewName');
  });

  it('deletes a client', async () => {
    const { initClientStore, createClient, deleteClient, listClients } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
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

  it('returns undefined for non-existent profile', async () => {
    const { initClientStore, createClient, createProfile, getProfileVersion } = await import('../clientStore');
    initClientStore();

    const client = createClient('NextCoreTI');
    const result = getProfileVersion(client.id, 'nonexistent-profile', 'nonexistent-version');
    assert.strictEqual(result, undefined);
  });
});
