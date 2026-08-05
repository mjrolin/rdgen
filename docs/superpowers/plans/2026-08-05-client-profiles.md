# Perfis de Cliente Criptografados — Plano de Implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Permitir salvar, de forma criptografada (AES-256-GCM), a configuração completa de cada cliente com histórico de versões, para que builds futuras possam ser geradas selecionando cliente + versão sem reconfigurar tudo do zero.

**Architecture:** Um novo serviço `clientStore` (espelhando o padrão de `jobStore`/`apiKeyStore`) persiste um JSON por cliente em `backend/data/clients/<id>.json`. Cada versão dentro do JSON contém o `config` (BuildConfig) criptografado com AES-256-GCM. Um novo router `clients.ts` expõe 6 endpoints REST. O frontend ganha um `ClientSelector` no topo do formulário e funções de API em `lib/api.ts`.

**Tech Stack:** Node.js `crypto` (built-in, AES-256-GCM), Express, TypeScript, `node --test` + `ts-node/register` para testes, Next.js/React no frontend.

## Global Constraints

- Algoritmo de criptografia: AES-256-GCM.
- Chave mestra: 32 bytes, armazenada como `CLIENT_PROFILE_KEY` no `.env` do backend.
- IV: 12 bytes aleatórios por gravação de versão, nunca reutilizado.
- Se `CLIENT_PROFILE_KEY` não estiver definida no ambiente, o backend deve recusar iniciar (falha explícita).
- Arquivos em `backend/data/clients/` criados com permissão `600` (chmod após write).
- Diretório `backend/data/clients/` com permissão `700`.
- `name` e `host` ficam em claro no JSON do cliente (para listagem sem decriptar).
- `ciphertext` contém o JSON serializado do `BuildConfig` completo.
- Cada versão tem `versionId` (UUID), `iv`, `authTag`, `ciphertext` (tudo base64).
- `latestVersionId` aponta para a versão mais recente.
- Autenticação: mesma usada pelas rotas admin existentes (sessão do painel / `X-Admin-Secret` header).
- Testes: `node --require ts-node/register --test 'src/**/__tests__/**/*.test.ts'` (padrão confirmado no servidor).
- Commits: formato `tipo: descrição em português` (ex: `feat: adiciona serviço de criptografia`).
- Nenhum placeholder — todo passo deve conter código real.

---

## File Structure

### Arquivos a criar

| Arquivo | Responsabilidade |
|---|---|
| `backend/src/services/cryptoService.ts` | Geração de chave, encriptação e decriptação AES-256-GCM; validação de `CLIENT_PROFILE_KEY` no startup. |
| `backend/src/services/clientStore.ts` | CRUD de perfis de cliente em disco (um JSON por cliente em `backend/data/clients/`). |
| `backend/src/routes/clients.ts` | Router Express com 6 endpoints REST para gerenciamento de clientes. |
| `backend/src/services/__tests__/cryptoService.test.ts` | Testes unitários do cryptoService. |
| `backend/src/services/__tests__/clientStore.test.ts` | Testes unitários do clientStore. |

### Arquivos a modificar

| Arquivo | Mudança |
|---|---|
| `backend/package.json` | Adicionar `supertest` e `@types/supertest` como devDependencies; adicionar script `"test"`. |
| `backend/src/index.ts` | Importar e registrar `clientsRouter`; adicionar validação de `CLIENT_PROFILE_KEY` no startup; garantir diretório `clients/`. |
| `.env.example` | Adicionar `CLIENT_PROFILE_KEY`. |
| `frontend/src/types/index.ts` | Adicionar interfaces `ClientListItem`, `ClientVersionInfo`, `ClientProfile`. |
| `frontend/src/lib/api.ts` | Adicionar funções `listClients`, `getClient`, `getClientVersion`, `createClient`, `addClientVersion`, `deleteClient`. |
| `frontend/src/app/page.tsx` | Adicionar `ClientSelector` no topo do formulário; lógica de auto-save ao gerar build. |

---

### Task 1: Infraestrutura de teste

**Files:**
- Modify: `backend/package.json`

**Interfaces:**
- Produces: `npm test` roda `node --require ts-node/register --test 'src/**/__tests__/**/*.test.ts'`

- [ ] **Step 1: Instalar supertest como devDependency no servidor**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npm install --save-dev supertest @types/supertest"
```

- [ ] **Step 2: Adicionar script de teste ao package.json**

No `backend/package.json`, adicionar no objeto `"scripts"`:

```json
"test": "node --require ts-node/register --test 'src/**/__tests__/**/*.test.ts'"
```

- [ ] **Step 3: Verificar que o script de teste funciona**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npm test 2>&1 | tail -10"
```

Expected: `# tests 0` / `# pass 0` / `# fail 0` (nenhum teste ainda, mas sem erros).

- [ ] **Step 4: Commit**

```bash
git add backend/package.json backend/package-lock.json
git commit -m "chore: adiciona supertest e script de teste"
```

---

### Task 2: Serviço de criptografia (cryptoService)

**Files:**
- Create: `backend/src/services/cryptoService.ts`
- Create: `backend/src/services/__tests__/cryptoService.test.ts`

**Interfaces:**
- Produces:
  - `ensureClientProfileKey(): void` — lança erro se `CLIENT_PROFILE_KEY` não estiver definida ou não for 32 bytes.
  - `encryptConfig(config: Record<string, unknown>): { iv: string; authTag: string; ciphertext: string }` — encripta o JSON do config.
  - `decryptConfig(iv: string, authTag: string, ciphertext: string): Record<string, unknown>` — decripta e retorna o config.
  - `generateClientProfileKey(): string` — gera uma chave aleatória de 32 bytes em hex (64 chars) para setup inicial.

- [ ] **Step 1: Escrever teste que falha — encrypt/decrypt round-trip**

```typescript
// backend/src/services/__tests__/cryptoService.test.ts
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';

const ORIGINAL_ENV = process.env.CLIENT_PROFILE_KEY;

// Shared test config (Record<string, unknown> to match encryptConfig signature)
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
    process.env.CLIENT_PROFILE_KEY = 'a'.repeat(64); // 32 bytes in hex
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
    // Tamper with ciphertext
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
```

- [ ] **Step 2: Rodar teste para confirmar que falha**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npm test 2>&1 | grep -E 'not ok|Cannot find|Error'"
```

Expected: `Cannot find module '../cryptoService'` — módulo ainda não existe.

- [ ] **Step 3: Implementar cryptoService**

```typescript
// backend/src/services/cryptoService.ts
import crypto from 'crypto';
import logger from '../utils/logger';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits, recommended for GCM
const KEY_LENGTH = 32; // 256 bits

/**
 * Valida que CLIENT_PROFILE_KEY está definida e tem o tamanho correto.
 * Deve ser chamada no startup do backend — lança erro se a chave não for válida.
 */
export function ensureClientProfileKey(): void {
  const keyHex = process.env.CLIENT_PROFILE_KEY;

  if (!keyHex) {
    throw new Error(
      'CLIENT_PROFILE_KEY não definida no .env. ' +
      'Gere uma com: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }

  const keyBuffer = Buffer.from(keyHex, 'hex');
  if (keyBuffer.length !== KEY_LENGTH) {
    throw new Error(
      `CLIENT_PROFILE_KEY deve ter ${KEY_LENGTH} bytes (${KEY_LENGTH * 2} chars hex). ` +
      `Atual: ${keyBuffer.length} bytes.`
    );
  }

  logger.info('CLIENT_PROFILE_KEY validated successfully');
}

/**
 * Gera uma chave aleatória de 32 bytes em formato hex.
 * Útil para setup inicial — o usuário copia para o .env.
 */
export function generateClientProfileKey(): string {
  return crypto.randomBytes(KEY_LENGTH).toString('hex');
}

/**
 * Retorna o buffer da chave mestra a partir do .env.
 * assume que ensureClientProfileKey() já foi chamada no startup.
 */
function getKeyBuffer(): Buffer {
  return Buffer.from(process.env.CLIENT_PROFILE_KEY!, 'hex');
}

/**
 * Encripta um BuildConfig como JSON usando AES-256-GCM.
 * Retorna iv, authTag e ciphertext, todos em base64.
 */
export function encryptConfig(config: Record<string, unknown>): {
  iv: string;
  authTag: string;
  ciphertext: string;
} {
  const key = getKeyBuffer();
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const plaintext = JSON.stringify(config);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  };
}

/**
 * Decripta um ciphertext AES-256-GCM de volta para um BuildConfig.
 * Lança erro se a chave estiver errada, o IV for reutilizado,
 * ou o ciphertext tiver sido adulterado (authTag mismatch).
 */
export function decryptConfig(
  iv: string,
  authTag: string,
  ciphertext: string
): Record<string, unknown> {
  const key = getKeyBuffer();

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString('utf8'));
}
```

- [ ] **Step 4: Rodar teste para confirmar que passa**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npm test 2>&1"
```

Expected: `# pass 3` / `# fail 0`.

- [ ] **Step 5: Commit**

```bash
git add backend/src/services/cryptoService.ts backend/src/services/__tests__/cryptoService.test.ts
git commit -m "feat: adiciona cryptoService com AES-256-GCM para perfis de cliente"
```

---

### Task 3: Serviço de persistência de clientes (clientStore)

**Files:**
- Create: `backend/src/services/clientStore.ts`
- Create: `backend/src/services/__tests__/clientStore.test.ts`

**Interfaces:**
- Consumes: `encryptConfig`, `decryptConfig` de `./cryptoService`; `BuildConfig` de `../types`.
- Produces:
  - `listClients(): ClientListItem[]` — lista todos os clientes (sem decriptar configs).
  - `getClient(id: string): ClientProfile | undefined` — retorna metadados + lista de versões (sem decriptar).
  - `getClientVersion(clientId: string, versionId: string): BuildConfig | undefined` — decripta e retorna o config de uma versão específica.
  - `createClient(name: string, host: string, config: BuildConfig): ClientProfile` — cria cliente com primeira versão criptografada.
  - `addClientVersion(id: string, config: BuildConfig): ClientProfile | undefined` — adiciona nova versão a cliente existente.
  - `deleteClient(id: string): boolean` — remove arquivo do cliente.
  - `initClientStore(): void` — cria diretório `backend/data/clients/` se não existir.

```typescript
// Tipos locais (não exportados do types/index.ts — apenas para o clientStore)
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

interface ClientListItem {
  id: string;
  name: string;
  host: string;
  versionCount: number;
  latestVersionId: string;
  updatedAt: string;
}
```

- [ ] **Step 1: Escrever teste que falha — createClient + listClients**

```typescript
// backend/src/services/__tests__/clientStore.test.ts
import { describe, it, before, after, beforeEach } from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';

const TEST_CLIENTS_DIR = path.join(__dirname, '../../data/clients');
const ORIGINAL_ENV = process.env.CLIENT_PROFILE_KEY;

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
    // Clean test data between tests
    if (fs.existsSync(TEST_CLIENTS_DIR)) {
      for (const f of fs.readdirSync(TEST_CLIENTS_DIR)) {
        if (f.endsWith('.json')) {
          fs.unlinkSync(path.join(TEST_CLIENTS_DIR, f));
        }
      }
    }
  });

  const sampleConfig = () => ({
    platform: 'windows' as const,
    version: '1.4.9' as const,
    configName: 'test',
    appName: 'RustDesk',
    filename: 'test',
    connectionDirection: 'Both' as const,
    disableInstallation: false,
    disableSettings: false,
    host: 'rd01.suporte.net.br',
    key: 'abc123',
    apiServer: 'https://api.example.com',
    urlLink: '',
    downloadLink: '',
    companyName: 'Test',
    approveMode: 'password-click' as const,
    permanentPassword: 'pass',
    denyLanDiscovery: false,
    enableDirectIp: true,
    autoCloseInactivity: false,
    allowHideConnectionWindow: false,
    theme: 'system' as const,
    themeMode: 'default' as const,
    permissionsMode: 'default' as const,
    permissionsType: 'full' as const,
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
    codecPreference: 'vp9' as const,
    enableHwCodec: true,
    fps: 30,
    displayMode: 'adaptive' as const,
  });

  it('creates a client and lists it', async () => {
    const clientStore = await import('../clientStore');
    clientStore.initClientStore();

    const client = clientStore.createClient('mrnery', 'rd01.suporte.net.br', sampleConfig());

    assert.ok(client.id);
    assert.strictEqual(client.name, 'mrnery');
    assert.strictEqual(client.host, 'rd01.suporte.net.br');
    assert.strictEqual(client.versions.length, 1);
    assert.strictEqual(client.latestVersionId, client.versions[0].versionId);

    const list = clientStore.listClients();
    assert.strictEqual(list.length, 1);
    assert.strictEqual(list[0].name, 'mrnery');
    assert.strictEqual(list[0].versionCount, 1);
  });

  it('adds a new version without overwriting previous', async () => {
    const clientStore = await import('../clientStore');
    clientStore.initClientStore();

    const client = clientStore.createClient('test', 'host.example.com', sampleConfig());
    const updated = clientStore.addClientVersion(client.id, {
      ...sampleConfig(),
      permanentPassword: 'new-password',
    });

    assert.ok(updated);
    assert.strictEqual(updated.versions.length, 2);
    assert.strictEqual(updated.latestVersionId, updated.versions[1].versionId);
    assert.notStrictEqual(
      updated.versions[0].versionId,
      updated.versions[1].versionId
    );
  });

  it('decrypts a specific version correctly', async () => {
    const clientStore = await import('../clientStore');
    clientStore.initClientStore();

    const config = sampleConfig();
    const client = clientStore.createClient('decrypt-test', 'host.example.com', config);

    const decrypted = clientStore.getClientVersion(client.id, client.versions[0].versionId);
    assert.ok(decrypted);
    assert.strictEqual((decrypted as any).permanentPassword, 'pass');
    assert.strictEqual((decrypted as any).host, 'rd01.suporte.net.br');
  });

  it('deletes a client', async () => {
    const clientStore = await import('../clientStore');
    clientStore.initClientStore();

    const client = clientStore.createClient('to-delete', 'host.example.com', sampleConfig());
    const deleted = clientStore.deleteClient(client.id);
    assert.strictEqual(deleted, true);

    const list = clientStore.listClients();
    assert.strictEqual(list.length, 0);
  });

  it('returns undefined for non-existent client', async () => {
    const clientStore = await import('../clientStore');
    clientStore.initClientStore();

    const result = clientStore.getClient('nonexistent');
    assert.strictEqual(result, undefined);
  });
});
```

- [ ] **Step 2: Rodar teste para confirmar que falha**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npm test 2>&1 | grep -E 'not ok|Cannot find'"
```

Expected: `Cannot find module '../clientStore'`.

- [ ] **Step 3: Implementar clientStore**

```typescript
// backend/src/services/clientStore.ts
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { encryptConfig, decryptConfig } from './cryptoService';
import logger from '../utils/logger';

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

/** Cria o diretório de clientes se não existir. Chamar no startup. */
export function initClientStore(): void {
  if (!fs.existsSync(CLIENTS_DIR)) {
    fs.mkdirSync(CLIENTS_DIR, { recursive: true });
    fs.chmodSync(CLIENTS_DIR, 0o700);
    logger.info(`Created clients directory: ${CLIENTS_DIR}`);
  }
}

/** Caminho do arquivo de um cliente. */
function clientFilePath(id: string): string {
  return path.join(CLIENTS_DIR, `${id}.json`);
}

/** Lê um cliente do disco. Retorna undefined se não existir. */
function readClientFile(id: string): ClientProfile | undefined {
  const filePath = clientFilePath(id);
  if (!fs.existsSync(filePath)) return undefined;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch (err) {
    logger.error(`Failed to read client file ${filePath}:`, err);
    return undefined;
  }
}

/** Escreve um cliente no disco com permissão 600. */
function writeClientFile(client: ClientProfile): void {
  const filePath = clientFilePath(client.id);
  fs.writeFileSync(filePath, JSON.stringify(client, null, 2));
  fs.chmodSync(filePath, 0o600);
}

/** Lista todos os clientes (sem decriptar configs). */
export function listClients(): ClientListItem[] {
  if (!fs.existsSync(CLIENTS_DIR)) return [];

  const files = fs.readdirSync(CLIENTS_DIR).filter(f => f.endsWith('.json'));
  const clients: ClientListItem[] = [];

  for (const file of files) {
    const client = readClientFile(file.replace('.json', ''));
    if (client) {
      clients.push({
        id: client.id,
        name: client.name,
        host: client.host,
        versionCount: client.versions.length,
        latestVersionId: client.latestVersionId,
        updatedAt: client.updatedAt,
      });
    }
  }

  return clients.sort(
    (a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
  );
}

/** Retorna metadados de um cliente + lista de versões (sem decriptar). */
export function getClient(id: string): ClientProfile | undefined {
  return readClientFile(id);
}

/** Decripta e retorna o BuildConfig de uma versão específica. */
export function getClientVersion(
  clientId: string,
  versionId: string
): Record<string, unknown> | undefined {
  const client = readClientFile(clientId);
  if (!client) return undefined;

  const version = client.versions.find(v => v.versionId === versionId);
  if (!version) return undefined;

  try {
    return decryptConfig(version.iv, version.authTag, version.ciphertext);
  } catch (err) {
    logger.error(`Failed to decrypt version ${versionId} of client ${clientId}:`, err);
    return undefined;
  }
}

/** Cria um novo cliente com sua primeira versão criptografada. */
export function createClient(
  name: string,
  host: string,
  config: Record<string, unknown>
): ClientProfile {
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

  writeClientFile(client);
  logger.info(`Created client ${id} (${name}) with 1 version`);
  return client;
}

/** Adiciona uma nova versão a um cliente existente. */
export function addClientVersion(
  id: string,
  config: Record<string, unknown>
): ClientProfile | undefined {
  const client = readClientFile(id);
  if (!client) return undefined;

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

  // Atualizar name/host em claro se mudaram no config
  if (typeof config.configName === 'string' && config.configName) {
    client.name = config.configName;
  }
  if (typeof config.host === 'string') {
    client.host = config.host as string;
  }

  writeClientFile(client);
  logger.info(`Added version ${versionId} to client ${id} (now ${client.versions.length} versions)`);
  return client;
}

/** Remove um cliente e todas as suas versões. */
export function deleteClient(id: string): boolean {
  const filePath = clientFilePath(id);
  if (!fs.existsSync(filePath)) return false;

  fs.unlinkSync(filePath);
  logger.info(`Deleted client ${id}`);
  return true;
}
```

- [ ] **Step 4: Rodar teste para confirmar que passa**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npm test 2>&1"
```

Expected: `# pass 9` (4 do cryptoService + 5 do clientStore) / `# fail 0`.

- [ ] **Step 5: Commit**

```bash
git add backend/src/services/clientStore.ts backend/src/services/__tests__/clientStore.test.ts
git commit -m "feat: adiciona clientStore para persistência de perfis de cliente"
```

---

### Task 4: Rotas REST para clientes

**Files:**
- Create: `backend/src/routes/clients.ts`
- Modify: `backend/src/index.ts`

**Interfaces:**
- Consumes: `listClients`, `getClient`, `getClientVersion`, `createClient`, `addClientVersion`, `deleteClient` de `../services/clientStore`; `requireAdmin` de `../middleware/apiKeyAuth`.
- Produces: 6 endpoints REST montados em `/api/clients`.

- [ ] **Step 1: Criar router clients.ts**

```typescript
// backend/src/routes/clients.ts
import { Router, Request, Response } from 'express';
import {
  listClients,
  getClient,
  getClientVersion,
  createClient,
  addClientVersion,
  deleteClient,
} from '../services/clientStore';
import { requireAdmin } from '../middleware/apiKeyAuth';
import logger from '../utils/logger';

const router = Router();

// Todas as rotas de clientes requerem autenticação admin
router.use(requireAdmin);

/**
 * GET /api/clients
 * Lista todos os clientes (sem decriptar configs).
 */
router.get('/', (req: Request, res: Response) => {
  try {
    const clients = listClients();
    res.json({ success: true, data: clients });
  } catch (error: any) {
    logger.error('Error listing clients:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/clients/:id
 * Detalhe de um cliente: metadados + lista de versões (sem decriptar).
 */
router.get('/:id', (req: Request, res: Response) => {
  try {
    const client = getClient(req.params.id);
    if (!client) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }
    res.json({ success: true, data: client });
  } catch (error: any) {
    logger.error('Error getting client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/clients/:id/versions/:versionId
 * Decripta e retorna o BuildConfig completo de uma versão.
 */
router.get('/:id/versions/:versionId', (req: Request, res: Response) => {
  try {
    const config = getClientVersion(req.params.id, req.params.versionId);
    if (!config) {
      return res.status(404).json({ success: false, error: 'Client or version not found' });
    }
    res.json({ success: true, data: config });
  } catch (error: any) {
    logger.error('Error getting client version:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/clients
 * Cria um novo cliente com sua primeira versão.
 * Body: { name: string, host: string, config: BuildConfig }
 */
router.post('/', (req: Request, res: Response) => {
  try {
    const { name, host, config } = req.body;

    if (!name || !host || !config) {
      return res.status(400).json({
        success: false,
        error: 'name, host and config are required',
      });
    }

    const client = createClient(name, host, config);
    res.status(201).json({ success: true, data: client });
  } catch (error: any) {
    logger.error('Error creating client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * PUT /api/clients/:id
 * Adiciona uma nova versão ao cliente existente (não sobrescreve anteriores).
 * Body: { config: BuildConfig }
 */
router.put('/:id', (req: Request, res: Response) => {
  try {
    const { config } = req.body;

    if (!config) {
      return res.status(400).json({ success: false, error: 'config is required' });
    }

    const client = addClientVersion(req.params.id, config);
    if (!client) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }

    res.json({ success: true, data: client });
  } catch (error: any) {
    logger.error('Error updating client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * DELETE /api/clients/:id
 * Remove o cliente e todas as suas versões.
 */
router.delete('/:id', (req: Request, res: Response) => {
  try {
    const deleted = deleteClient(req.params.id);
    if (!deleted) {
      return res.status(404).json({ success: false, error: 'Client not found' });
    }
    res.json({ success: true, message: 'Client deleted' });
  } catch (error: any) {
    logger.error('Error deleting client:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
```

- [ ] **Step 2: Integrar no index.ts — registrar rota + validação de chave no startup**

No `backend/src/index.ts`, fazer as seguintes alterações:

Adicionar imports após os imports existentes:

```typescript
import clientsRoutes from './routes/clients';
import { ensureClientProfileKey } from './services/cryptoService';
import { initClientStore } from './services/clientStore';
```

Antes de `const app = express();`, adicionar validação de chave:

```typescript
// Validate CLIENT_PROFILE_KEY at startup (fail-fast if missing/invalid)
ensureClientProfileKey();
```

Após a linha `app.use('/api', apiRoutes);`, adicionar:

```typescript
// Client profiles routes (encrypted client management)
app.use('/api/clients', clientsRoutes);
```

E após `app.listen(...)`, dentro do callback, adicionar:

```typescript
// Ensure clients data directory exists
initClientStore();
```

- [ ] **Step 3: Verificar que o backend compila**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npx tsc --noEmit 2>&1"
```

Expected: `TSC_OK` (sem erros).

- [ ] **Step 4: Gerar CLIENT_PROFILE_KEY e adicionar ao .env**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real && echo '' >> .env && echo '# Client Profile Encryption Key (AES-256, 32 bytes in hex)' >> .env && echo \"CLIENT_PROFILE_KEY=\$(node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\")\" >> .env && chmod 600 .env"
```

- [ ] **Step 5: Atualizar .env.example**

Adicionar ao `.env.example`:

```
# =============================================================================
# Client Profile Encryption (REQUIRED)
# =============================================================================

# AES-256 master key for encrypting client profiles (32 bytes in hex = 64 chars)
# Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
CLIENT_PROFILE_KEY=your-64-char-hex-key-here
```

- [ ] **Step 6: Rodar todos os testes**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npm test 2>&1"
```

Expected: `# pass 9` / `# fail 0`.

- [ ] **Step 7: Rebuild e restart do backend**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npx tsc && systemctl restart rdgen-backend && sleep 2 && systemctl status rdgen-backend --no-pager | head -15"
```

Expected: `active (running)`.

- [ ] **Step 8: Commit**

```bash
git add backend/src/routes/clients.ts backend/src/index.ts .env.example
git commit -m "feat: adiciona rotas REST para perfis de cliente com autenticação admin"
```

---

### Task 5: Frontend — Tipos, API e ClientSelector

**Files:**
- Modify: `frontend/src/types/index.ts`
- Modify: `frontend/src/lib/api.ts`
- Create: `frontend/src/components/ClientSelector.tsx`
- Modify: `frontend/src/app/page.tsx`

**Interfaces:**
- Consumes: `listClients`, `getClient`, `getClientVersion`, `createClient`, `addClientVersion`, `deleteClient` via API HTTP.
- Produces: Componente `ClientSelector` renderizado no topo do formulário de build.

- [ ] **Step 1: Adicionar tipos de cliente ao frontend**

No final de `frontend/src/types/index.ts`, antes do último `};` do `CONFIG_TEMPLATES`, adicionar:

```typescript
// =====================
// Client Profile types
// =====================

export interface ClientListItem {
  id: string;
  name: string;
  host: string;
  versionCount: number;
  latestVersionId: string;
  updatedAt: string;
}

export interface ClientVersionInfo {
  versionId: string;
  createdAt: string;
  label: string;
}

export interface ClientProfile {
  id: string;
  name: string;
  host: string;
  createdAt: string;
  updatedAt: string;
  latestVersionId: string;
  versions: ClientVersionInfo[];
}
```

- [ ] **Step 2: Adicionar funções de API para clientes**

No final de `frontend/src/lib/api.ts`, adicionar:

```typescript
// =====================
// Client Profile API
// =====================

export async function listClients(): Promise<ApiResponse<ClientListItem[]>> {
  try {
    const response = await api.get<ApiResponse<ClientListItem[]>>('/clients');
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to list clients',
    };
  }
}

export async function getClient(clientId: string): Promise<ApiResponse<ClientProfile>> {
  try {
    const response = await api.get<ApiResponse<ClientProfile>>(`/clients/${clientId}`);
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to get client',
    };
  }
}

export async function getClientVersion(
  clientId: string,
  versionId: string
): Promise<ApiResponse<BuildConfig>> {
  try {
    const response = await api.get<ApiResponse<BuildConfig>>(
      `/clients/${clientId}/versions/${versionId}`
    );
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to get client version',
    };
  }
}

export async function createClient(
  name: string,
  host: string,
  config: BuildConfig
): Promise<ApiResponse<ClientProfile>> {
  try {
    const response = await api.post<ApiResponse<ClientProfile>>('/clients', {
      name,
      host,
      config,
    });
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to create client',
    };
  }
}

export async function addClientVersion(
  clientId: string,
  config: BuildConfig
): Promise<ApiResponse<ClientProfile>> {
  try {
    const response = await api.put<ApiResponse<ClientProfile>>(`/clients/${clientId}`, {
      config,
    });
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to add client version',
    };
  }
}

export async function deleteClient(clientId: string): Promise<ApiResponse<void>> {
  try {
    const response = await api.delete<ApiResponse<void>>(`/clients/${clientId}`);
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to delete client',
    };
  }
}
```

- [ ] **Step 3: Adicionar import dos tipos de cliente no frontend types**

No topo de `frontend/src/types/index.ts`, garantir que os tipos `ClientListItem`, `ClientVersionInfo`, `ClientProfile` estão disponíveis (eles foram adicionados no Step 1, no final do arquivo — o TS os exporta automaticamente).

- [ ] **Step 4: Criar componente ClientSelector**

```tsx
// frontend/src/components/ClientSelector.tsx
'use client';

import { useState, useEffect } from 'react';
import { BuildConfig, ClientListItem, ClientProfile } from '@/types';
import { listClients, getClient, getClientVersion } from '@/lib/api';
import toast from 'react-hot-toast';

interface ClientSelectorProps {
  currentConfig: BuildConfig;
  onConfigLoad: (config: BuildConfig) => void;
  selectedClientId: string | null;
  onSelectClient: (clientId: string | null) => void;
}

export default function ClientSelector({
  currentConfig,
  onConfigLoad,
  selectedClientId,
  onSelectClient,
}: ClientSelectorProps) {
  const [clients, setClients] = useState<ClientListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingVersion, setLoadingVersion] = useState(false);
  const [selectedClient, setSelectedClient] = useState<ClientProfile | null>(null);
  const [selectedVersionId, setSelectedVersionId] = useState<string>('');
  const [showPassword, setShowPassword] = useState(false);

  // Load client list on mount
  useEffect(() => {
    loadClients();
  }, []);

  const loadClients = async () => {
    setLoading(true);
    const result = await listClients();
    if (result.success && result.data) {
      setClients(result.data);
    }
    setLoading(false);
  };

  // When a client is selected, fetch its details
  const handleClientChange = async (clientId: string) => {
    if (clientId === 'new') {
      onSelectClient(null);
      setSelectedClient(null);
      setSelectedVersionId('');
      return;
    }

    onSelectClient(clientId);
    setShowPassword(false);

    const result = await getClient(clientId);
    if (result.success && result.data) {
      setSelectedClient(result.data);
      setSelectedVersionId(result.data.latestVersionId);
      // Auto-load latest version
      await loadVersion(clientId, result.data.latestVersionId);
    }
  };

  // Load a specific version into the form
  const loadVersion = async (clientId: string, versionId: string) => {
    setLoadingVersion(true);
    const result = await getClientVersion(clientId, versionId);
    if (result.success && result.data) {
      onConfigLoad(result.data as unknown as BuildConfig);
      toast.success('Configuração carregada do perfil');
    } else {
      toast.error(result.error || 'Erro ao carregar versão');
    }
    setLoadingVersion(false);
  };

  const handleVersionChange = async (versionId: string) => {
    setSelectedVersionId(versionId);
    setShowPassword(false);
    if (selectedClientId) {
      await loadVersion(selectedClientId, versionId);
    }
  };

  return (
    <div className="section mb-4">
      <h2 className="section-title">
        <i className="fas fa-users text-sm"></i>
        Cliente
      </h2>

      <div className="flex gap-3 items-end">
        {/* Client selector */}
        <div className="flex-1">
          <label className="input-label">Perfil do cliente</label>
          <select
            value={selectedClientId || 'new'}
            onChange={(e) => handleClientChange(e.target.value)}
            className="input-field"
            disabled={loading}
          >
            <option value="new">➕ Novo Cliente</option>
            {clients.map((client) => (
              <option key={client.id} value={client.id}>
                {client.name} — {client.host} ({client.versionCount} versões)
              </option>
            ))}
          </select>
        </div>

        {/* Version selector (only shown when a client is selected) */}
        {selectedClient && (
          <div className="flex-1">
            <label className="input-label">Versão de referência</label>
            <select
              value={selectedVersionId}
              onChange={(e) => handleVersionChange(e.target.value)}
              className="input-field"
              disabled={loadingVersion}
            >
              {selectedClient.versions
                .slice()
                .reverse()
                .map((v, idx) => (
                  <option key={v.versionId} value={v.versionId}>
                    {idx === 0 ? '⭐ ' : ''}v{selectedClient.versions.length - idx} —{' '}
                    {new Date(v.createdAt).toLocaleDateString('pt-BR')}
                    {v.label ? ` (${v.label})` : ''}
                  </option>
                ))}
            </select>
          </div>
        )}
      </div>

      {/* Password preview when client is selected */}
      {selectedClient && currentConfig.permanentPassword && (
        <div className="mt-2 flex items-center gap-2">
          <span className="text-gray-400 text-xs">Senha permanente:</span>
          <span className="text-white text-xs font-mono">
            {showPassword ? currentConfig.permanentPassword : '••••••••'}
          </span>
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="text-gray-400 hover:text-white text-xs"
          >
            <i className={`fas ${showPassword ? 'fa-eye-slash' : 'fa-eye'}`}></i>
          </button>
        </div>
      )}

      {loadingVersion && (
        <div className="mt-2 text-yellow-400 text-xs">
          <i className="fas fa-spinner fa-spin mr-1"></i>
          Carregando configuração...
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Integrar ClientSelector no page.tsx**

No `frontend/src/app/page.tsx`:

Adicionar import:

```typescript
import ClientSelector from '@/components/ClientSelector';
```

Adicionar state após os states existentes:

```typescript
const [selectedClientId, setSelectedClientId] = useState<string | null>(null);
```

No JSX, logo após `<ConfigManager ... />` e antes do `<h1>`, inserir:

```tsx
<ClientSelector
  currentConfig={config}
  onConfigLoad={setConfig}
  selectedClientId={selectedClientId}
  onSelectClient={setSelectedClientId}
/>
```

- [ ] **Step 6: Verificar que o frontend compila**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/frontend && npx next build 2>&1 | tail -20"
```

Expected: `Compiled successfully` sem erros.

- [ ] **Step 7: Rebuild e restart do frontend**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/frontend && npx next build && systemctl restart rdgen-frontend && sleep 3 && systemctl status rdgen-frontend --no-pager | head -15"
```

Expected: `active (running)`.

- [ ] **Step 8: Commit**

```bash
git add frontend/src/types/index.ts frontend/src/lib/api.ts frontend/src/components/ClientSelector.tsx frontend/src/app/page.tsx
git commit -m "feat: adiciona seletor de cliente no frontend com carregamento de perfis"
```

---

### Task 6: Auto-save de perfil ao gerar build

**Files:**
- Modify: `frontend/src/app/page.tsx`

**Interfaces:**
- Consumes: `createClient`, `addClientVersion` de `@/lib/api`; `selectedClientId` state.
- Produces: Ao clicar "Gerar", o perfil do cliente é salvo automaticamente (cria ou adiciona versão) em paralelo ao disparo do build.

- [ ] **Step 1: Adicionar import das funções de cliente**

No topo de `frontend/src/app/page.tsx`, garantir import:

```typescript
import { startBuild, createClient, addClientVersion } from '@/lib/api';
```

- [ ] **Step 2: Modificar handleGenerate para auto-salvar perfil**

Substituir a função `handleGenerate` por:

```typescript
const handleGenerate = async () => {
  const error = validateConfig();
  if (error) {
    toast.error(error);
    return;
  }

  setIsBuilding(true);
  setCurrentJob(null);

  const buildConfig = {
    ...config,
    filename: config.filename || config.configName,
  };

  // Auto-save client profile (fire-and-forget alongside build)
  const saveProfile = async () => {
    try {
      if (selectedClientId) {
        // Existing client — add new version
        const result = await addClientVersion(selectedClientId, buildConfig);
        if (result.success) {
          toast.success('Perfil do cliente atualizado', { id: 'profile-save' });
        }
      } else if (config.configName) {
        // New client — create profile (only if user filled configName)
        const result = await createClient(config.configName, config.host, buildConfig);
        if (result.success && result.data) {
          setSelectedClientId(result.data.id);
          toast.success('Perfil de cliente criado', { id: 'profile-save' });
        }
      }
    } catch {
      // Profile save failure should not block the build
      console.error('Failed to save client profile');
    }
  };

  // Run build and profile save in parallel
  const [buildResult] = await Promise.all([startBuild(buildConfig), saveProfile()]);

  if (buildResult.success && buildResult.data) {
    setCurrentJob(buildResult.data);
    toast.success('Build started!');
  } else {
    toast.error(buildResult.error || 'Failed to start build');
    setIsBuilding(false);
  }
};
```

- [ ] **Step 3: Verificar que o frontend compila**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/frontend && npx next build 2>&1 | tail -10"
```

Expected: `Compiled successfully`.

- [ ] **Step 4: Rebuild e restart**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/frontend && npx next build && systemctl restart rdgen-frontend && sleep 3 && systemctl status rdgen-frontend --no-pager | head -10"
```

Expected: `active (running)`.

- [ ] **Step 5: Commit**

```bash
git add frontend/src/app/page.tsx
git commit -m "feat: auto-salva perfil do cliente ao gerar build"
```

---

### Task 7: Verificação final e commit de segurança

**Files:**
- Nenhum arquivo novo — apenas verificação.

**Interfaces:**
- Nenhuma.

- [ ] **Step 1: Rodar todos os testes no servidor**

```bash
ssh root@192.168.101.81 "cd /opt/rdgen/rdgen-real/backend && npm test 2>&1"
```

Expected: Todos os testes passando.

- [ ] **Step 2: Verificar que o backend está rodando**

```bash
ssh root@192.168.101.81 "systemctl status rdgen-backend --no-pager | head -10"
```

Expected: `active (running)`.

- [ ] **Step 3: Verificar que o frontend está rodando**

```bash
ssh root@192.168.101.81 "systemctl status rdgen-frontend --no-pager | head -10"
```

Expected: `active (running)`.

- [ ] **Step 4: Testar endpoint de clientes via curl**

```bash
ssh root@192.168.101.81 "curl -s http://127.0.0.1:4000/api/clients -H 'X-Admin-Secret: '\$(grep ADMIN_SECRET /opt/rdgen/rdgen-real/.env | cut -d= -f2) | python3 -m json.tool"
```

Expected: `{"success": true, "data": []}` (lista vazia — nenhum cliente ainda).

- [ ] **Step 5: Verificar permissões dos arquivos de dados**

```bash
ssh root@192.168.101.81 "ls -la /opt/rdgen/rdgen-real/backend/data/ && ls -la /opt/rdgen/rdgen-real/backend/data/clients/ 2>/dev/null"
```

Expected: `backend/data/` com `drwx------`, `backend/data/clients/` com `drwx------`.

- [ ] **Step 6: Push final**

```bash
git push origin master
```

- [ ] **Step 7: Acessar a UI e testar manualmente**

Acessar `https://rdgen.nextcoreti.com.br/`, verificar que:
1. O seletor de cliente aparece no topo do formulário.
2. A opção "Novo Cliente" está selecionada por padrão.
3. Preencher o formulário, clicar em "Gerar" — o perfil deve ser criado automaticamente.
4. Recarregar a página — o cliente deve aparecer no seletor.
5. Selecionar o cliente — os campos devem ser preenchidos automaticamente.
6. A senha permanente deve aparecer mascarada com botão de mostrar.

---

## Resumo de commits

| Task | Commit |
|---|---|
| 1 | `chore: adiciona supertest e script de teste` |
| 2 | `feat: adiciona cryptoService com AES-256-GCM para perfis de cliente` |
| 3 | `feat: adiciona clientStore para persistência de perfis de cliente` |
| 4 | `feat: adiciona rotas REST para perfis de cliente com autenticação admin` |
| 5 | `feat: adiciona seletor de cliente no frontend com carregamento de perfis` |
| 6 | `feat: auto-salva perfil do cliente ao gerar build` |
| 7 | Verificação final (sem commit adicional) |
