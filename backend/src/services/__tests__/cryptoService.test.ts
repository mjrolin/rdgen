import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';

const ORIGINAL_ENV = process.env.CLIENT_PROFILE_KEY;

const sampleConfig: Record<string, unknown> = {
  platform: 'windows',
  version: '1.4.9',
  configName: 'test-client',
  appName: 'RustDesk',
  filename: 'test-client',
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

describe('cryptoService', () => {
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

  it('encrypts and decrypts a BuildConfig round-trip', async () => {
    const { encryptConfig, decryptConfig } = await import('../cryptoService');
    const encrypted = encryptConfig(sampleConfig);
    assert.ok(encrypted.iv, 'iv should be present');
    assert.ok(encrypted.authTag, 'authTag should be present');
    assert.ok(encrypted.ciphertext, 'ciphertext should be present');
    const decrypted = decryptConfig(encrypted.iv, encrypted.authTag, encrypted.ciphertext);
    assert.deepStrictEqual(decrypted, sampleConfig);
  });

  it('produces different ciphertext for same input (random IV)', async () => {
    const { encryptConfig } = await import('../cryptoService');
    const a = encryptConfig(sampleConfig);
    const b = encryptConfig(sampleConfig);
    assert.notStrictEqual(a.iv, b.iv, 'IVs should differ');
    assert.notStrictEqual(a.ciphertext, b.ciphertext, 'ciphertexts should differ');
  });

  it('fails to decrypt with tampered ciphertext', async () => {
    const { encryptConfig, decryptConfig } = await import('../cryptoService');
    const encrypted = encryptConfig(sampleConfig);
    const tampered = encrypted.ciphertext.slice(0, -4) + 'XXXX';
    assert.throws(() => {
      decryptConfig(encrypted.iv, encrypted.authTag, tampered);
    });
  });

  it('generateClientProfileKey returns 64-char hex string', async () => {
    const { generateClientProfileKey } = await import('../cryptoService');
    const key = generateClientProfileKey();
    assert.strictEqual(key.length, 64);
    assert.match(key, /^[0-9a-f]{64}$/);
  });
});
