# RDGen - Instalação Manual

## Requisitos
- Ubuntu/Debian com 1GB+ RAM
- Node.js 18+
- Nginx
- Conta GitHub com Personal Access Token

## 1. Preparar Sistema

```bash
apt update && apt install -y nodejs npm nginx python3-nacl
```

## 2. Fork do Repositório

Fazer fork de `https://github.com/bryangerlach/rdgen` para sua conta GitHub.

## 3. Clonar e Estruturar

```bash
mkdir -p /opt/rdgen/rdgen-real
cd /opt/rdgen/rdgen-real

# Clonar referência
git clone https://github.com/bryangerlach/rdgen /tmp/rdgen-ref
```

## 4. Backend (Express.js)

```bash
mkdir -p backend/src/{routes,services}
cd backend
npm init -y
npm install express cors dotenv uuid @octokit/rest
npm install -D typescript @types/node @types/express @types/cors @types/uuid
```

Criar `backend/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"]
}
```

Criar `backend/src/index.ts`:
```typescript
import express from 'express';
import cors from 'cors';
import apiRoutes from './routes/api';

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/api', apiRoutes);

app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});
```

Criar `backend/src/services/githubService.ts`:
```typescript
import { Octokit } from '@octokit/rest';

const token = process.env.GITHUB_TOKEN || '';
const owner = process.env.GITHUB_OWNER || '';
const repo = process.env.GITHUB_REPO || 'rdgen';

export const mockMode = !token;
const octokit = token ? new Octokit({ auth: token }) : null;

export async function triggerWorkflow(workflowFile: string, inputs: Record<string, string>) {
  if (mockMode || !octokit) {
    return { mock: true, runId: Date.now() };
  }

  await octokit.actions.createWorkflowDispatch({
    owner,
    repo,
    workflow_id: workflowFile,
    ref: 'master',
    inputs
  });

  // Buscar run ID
  await new Promise(r => setTimeout(r, 3000));
  const runs = await octokit.actions.listWorkflowRuns({
    owner, repo,
    workflow_id: workflowFile,
    per_page: 1
  });

  return { runId: runs.data.workflow_runs[0]?.id };
}

export async function getWorkflowStatus(runId: number) {
  if (mockMode || !octokit) return { status: 'completed', conclusion: 'success' };

  const run = await octokit.actions.getWorkflowRun({ owner, repo, run_id: runId });
  return { status: run.data.status, conclusion: run.data.conclusion };
}
```

Criar `backend/src/routes/api.ts`:
```typescript
import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { triggerWorkflow, getWorkflowStatus, mockMode } from '../services/githubService';

const router = Router();
const jobs: Map<string, any> = new Map();

const WORKFLOW_MAP: Record<string, string> = {
  'windows': 'generator-windows.yml',
  'windows-x86': 'generator-windows-x86.yml',
  'linux': 'generator-linux.yml',
  'android': 'generator-android.yml',
  'macos': 'generator-macos.yml'
};

router.get('/health', (req, res) => {
  res.json({ success: true, data: { status: 'healthy', mockMode } });
});

router.post('/build', async (req, res) => {
  try {
    const config = req.body;
    const uuid = uuidv4();
    const jobId = uuid.substring(0, 8);

    const workflowFile = WORKFLOW_MAP[config.platform] || 'generator-windows.yml';

    const customJson = JSON.stringify({
      host: config.host || '',
      key: config.key || '',
      api: config.apiServer || '',
      'relay-server': config.host || ''
    });

    const inputs = {
      server: config.host || '',
      key: config.key || '',
      apiServer: config.apiServer || '',
      custom: Buffer.from(customJson).toString('base64'),
      uuid: uuid,
      appname: config.appName || 'rustdesk',
      filename: config.filename || 'rustdesk',
      extras: JSON.stringify({
        version: config.version || '1.4.4',
        delayFix: config.delayFix ? 'true' : 'false'
      })
    };

    const result = await triggerWorkflow(workflowFile, inputs);

    jobs.set(jobId, {
      id: jobId,
      uuid,
      config,
      status: 'queued',
      workflowRunId: result.runId,
      createdAt: new Date().toISOString()
    });

    res.json({ success: true, data: { jobId, uuid } });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get('/status/:jobId', async (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ success: false, error: 'Job not found' });
  }

  if (job.workflowRunId && job.status !== 'completed') {
    const status = await getWorkflowStatus(job.workflowRunId);
    if (status.status === 'completed') {
      job.status = status.conclusion === 'success' ? 'completed' : 'failed';
    } else {
      job.status = status.status || 'in_progress';
    }
  }

  res.json({ success: true, data: job });
});

// Callback do GitHub Actions
router.post('/updategh', (req, res) => {
  const { uuid, status, download_url, msi_url } = req.body;

  for (const [id, job] of jobs) {
    if (job.uuid === uuid) {
      job.status = status || job.status;
      if (download_url) job.artifactUrl = download_url;
      if (msi_url) job.artifactMsiUrl = msi_url;
      break;
    }
  }

  res.json({ success: true });
});

export default router;
```

Compilar backend:
```bash
npx tsc
```

## 5. Frontend (Next.js)

```bash
cd /opt/rdgen/rdgen-real
npx create-next-app@14 frontend --typescript --tailwind --app --no-src-dir
cd frontend
mv app src/app  # se necessário ajustar estrutura
```

Criar `frontend/src/types/index.ts`:
```typescript
export type Platform = 'windows' | 'windows-x86' | 'linux' | 'android' | 'macos';
export type RustDeskVersion = 'nightly' | '1.4.4' | '1.4.3' | '1.4.2' | '1.4.1' | '1.4.0';

export interface BuildConfig {
  platform: Platform;
  version: RustDeskVersion;
  configName: string;
  appName: string;
  filename: string;
  host: string;
  key: string;
  apiServer: string;
  delayFix: boolean;
  // ... adicionar outros campos conforme necessário
}

export const DEFAULT_BUILD_CONFIG: BuildConfig = {
  platform: 'windows',
  version: '1.4.4',
  configName: 'MyRustDesk',
  appName: 'RustDesk',
  filename: 'rustdesk',
  host: '',
  key: '',
  apiServer: '',
  delayFix: true
};
```

Criar página principal em `frontend/src/app/page.tsx` com formulário para configuração (ver código completo no projeto).

Build frontend:
```bash
NODE_OPTIONS="--max-old-space-size=1024" npm run build
```

## 6. Configurar Nginx

Criar `/etc/nginx/sites-available/rdgen`:
```nginx
server {
    listen 5000;
    server_name _;
    client_max_body_size 50M;

    location /api/ {
        proxy_pass http://127.0.0.1:4000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 300s;
    }

    location /updategh {
        proxy_pass http://127.0.0.1:4000/api/updategh;
        proxy_set_header Host $host;
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
    }
}
```

Ativar:
```bash
ln -sf /etc/nginx/sites-available/rdgen /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
```

## 7. Configurar GitHub

### 7.1 Criar Personal Access Token
1. GitHub → Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. Scopes: `repo`, `workflow`

### 7.2 Adicionar Secret GENURL ao Fork

```bash
# Obter chave pública do repo
curl -s -H "Authorization: token SEU_TOKEN" \
  "https://api.github.com/repos/SEU_USER/rdgen/actions/secrets/public-key"

# Encriptar e adicionar secret (usar script Python)
python3 << 'EOF'
from nacl import public
import base64

public_key_b64 = "CHAVE_DO_PASSO_ANTERIOR"
secret_value = "http://SEU_IP:5000"

public_key = public.PublicKey(base64.b64decode(public_key_b64))
sealed_box = public.SealedBox(public_key)
encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
print(base64.b64encode(encrypted).decode("utf-8"))
EOF

# Adicionar secret
curl -X PUT \
  -H "Authorization: token SEU_TOKEN" \
  "https://api.github.com/repos/SEU_USER/rdgen/actions/secrets/GENURL" \
  -d '{"encrypted_value": "VALOR_ENCRIPTADO", "key_id": "KEY_ID"}'
```

Ou manualmente em: `https://github.com/SEU_USER/rdgen/settings/secrets/actions`

### 7.3 Ativar GitHub Actions no Fork
Ir a `https://github.com/SEU_USER/rdgen/actions` e ativar workflows.

## 8. Criar .env

```bash
cat > /opt/rdgen/rdgen-real/.env << 'EOF'
GITHUB_TOKEN=ghp_xxxxx
GITHUB_OWNER=seu_usuario
GITHUB_REPO=rdgen
PORT=5000
GEN_URL=http://SEU_IP:5000
EOF
```

## 9. Iniciar Serviços

```bash
# Backend
cd /opt/rdgen/rdgen-real/backend
source ../.env
GITHUB_TOKEN=$GITHUB_TOKEN GITHUB_OWNER=$GITHUB_OWNER PORT=4000 node dist/index.js &

# Frontend
cd /opt/rdgen/rdgen-real/frontend
PORT=3000 npm run start &
```

## 10. Testar

Aceder a `http://SEU_IP:5000`

Verificar:
- Backend: `curl http://localhost:4000/api/health`
- Frontend: `curl http://localhost:3000`

## Troubleshooting

**Build sem memória:**
```bash
NODE_OPTIONS="--max-old-space-size=1024" npm run build
```

**Porta em uso:**
```bash
lsof -i :3000
kill PID
```

**Verificar logs:**
```bash
# Backend
curl http://localhost:4000/api/health

# Nginx
tail -f /var/log/nginx/error.log
```
