# RDGen - Arquitetura do Sistema

## Visão Geral

RDGen é um sistema para gerar clientes RustDesk customizados. Permite configurar:
- Servidor e chave de conexão
- Permissões de acesso
- Aparência (ícone, logo, tema)
- Comportamento do cliente
- Senha permanente
- E muito mais

## Componentes

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Frontend     │────▶│     Backend     │────▶│  GitHub Actions │
│   (Next.js)     │     │   (Node.js)     │     │   (Workflows)   │
│   Port 3000     │     │   Port 4000     │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │                        │
                               ▼                        ▼
                        ┌─────────────┐         ┌─────────────────┐
                        │  jobs.json  │         │ mjrolin/rustdesk│
                        │  (estado)   │         │    (fork)       │
                        └─────────────┘         └─────────────────┘
```

## Frontend (Next.js)

**Localização:** `/opt/rdgen/rdgen-real/frontend/`

### Estrutura:
```
frontend/
├── src/
│   ├── app/
│   │   ├── page.tsx              # Página principal
│   │   └── api-docs/page.tsx     # Documentação da API
│   ├── components/
│   │   ├── PlatformSelector.tsx  # Seleção de plataforma
│   │   ├── TemplateSelector.tsx  # Templates predefinidos
│   │   ├── GeneralSection.tsx    # Config geral
│   │   ├── ServerSection.tsx     # Config servidor
│   │   ├── SecuritySection.tsx   # Config segurança
│   │   ├── VisualSection.tsx     # Config visual
│   │   ├── PermissionsSection.tsx# Config permissões
│   │   ├── CodeChangesSection.tsx# Patches de código
│   │   ├── OtherSection.tsx      # Outras configs
│   │   ├── ConfigManager.tsx     # Salvar/carregar configs
│   │   └── BuildProgress.tsx     # Progresso do build
│   ├── lib/
│   │   └── api.ts                # Cliente da API
│   └── types/
│       └── index.ts              # Tipos TypeScript
```

### Templates Disponíveis:
- **Admin:** Controle total, todas permissões
- **Host:** Apenas recebe conexões, sem abas extras
- **Cliente:** Apenas faz conexões de saída
- **Personalizado:** Configuração manual

## Backend (Node.js)

**Localização:** `/opt/rdgen/rdgen-real/backend/`

### Estrutura:
```
backend/
├── src/
│   ├── index.ts                  # Entry point
│   ├── routes/
│   │   └── api.ts                # Rotas da API
│   ├── services/
│   │   ├── githubService.ts      # Integração GitHub
│   │   └── jobStore.ts           # Gerenciamento de jobs
│   ├── utils/
│   │   ├── configBuilder.ts      # Gera JSON de config
│   │   └── logger.ts             # Logging
│   └── types/
│       └── index.ts              # Tipos TypeScript
├── dist/                         # Código compilado
└── data/
    └── jobs.json                 # Estado dos jobs
```

### Endpoints da API:

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/build` | Inicia novo build |
| GET | `/api/build/:id` | Status de um build |
| GET | `/api/builds` | Lista todos builds |
| POST | `/api/build/:id/cancel` | Cancela build |
| GET | `/api/artifact/:id` | Download do artefato |
| POST | `/api/save_custom_client` | Recebe artefato do workflow |
| GET | `/api/get_png` | Serve ícone/logo para workflow |

### Fluxo de Build:

1. Frontend envia POST `/api/build` com `BuildConfig`
2. Backend gera UUID e cria job
3. Backend chama `buildWorkflowInputs()` para gerar inputs
4. Backend dispara workflow via GitHub API
5. Backend faz polling do status do workflow
6. Workflow envia artefatos via POST `/api/save_custom_client`
7. Frontend faz polling de GET `/api/build/:id`

## GitHub Workflows

**Localização:** `/tmp/rdgen-github/.github/workflows/`

### Workflows Disponíveis:

| Arquivo | Plataforma |
|---------|------------|
| `generator-windows.yml` | Windows x64 |
| `generator-windows-x86.yml` | Windows x86 |
| `generator-linux.yml` | Linux |
| `generator-android.yml` | Android |
| `generator-macos.yml` | macOS |

### Inputs do Workflow:

```yaml
inputs:
  server:      # Endereço do servidor RustDesk
  key:         # Chave pública do servidor
  apiServer:   # URL da API do servidor
  custom:      # JSON de config codificado em BASE64
  uuid:        # Identificador único do build
  iconlink:    # JSON com info para baixar ícone
  logolink:    # JSON com info para baixar logo
  appname:     # Nome do aplicativo
  filename:    # Nome do arquivo de saída
  extras:      # JSON com configs extras (rdgen, version, etc)
```

### Etapas Principais do Workflow:

1. **Checkout** - Clona `mjrolin/rustdesk`
2. **Patches** - Aplica `allowCustom.py`, `removeSetupServerTip.diff`
3. **Change appname** - Muda nome do app no código
4. **Change company** - Muda nome da empresa
5. **Set server/key** - Configura servidor
6. **Install dependencies** - Flutter, Rust, LLVM, vcpkg
7. **Icon/Logo** - Baixa e aplica ícones customizados
8. **Build** - Compila RustDesk
9. **Create custom_.txt** - Escreve configurações
10. **Build portable** - Gera executável auto-extraível
11. **Build MSI** - Gera instalador MSI
12. **Sign** - Assina com certificado (Google Cloud KMS + Jsign)
13. **Upload** - Envia artefatos para o backend

## Fluxo do custom_.txt

```
┌─────────────────────────────────────────────────────────────────┐
│                         BACKEND                                  │
│                                                                  │
│  BuildConfig ──▶ buildCustomJson() ──▶ JSON ──▶ base64 encode  │
│                                                                  │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼ inputs.custom (string base64)
┌──────────────────────────────────────────────────────────────────┐
│                       GITHUB WORKFLOW                             │
│                                                                   │
│  echo -n "${{ inputs.custom }}" | cat > ./rustdesk/custom_.txt   │
│                                                                   │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼ custom_.txt contém string base64
┌──────────────────────────────────────────────────────────────────┐
│                         RUSTDESK                                  │
│                                                                   │
│  read_custom_client() ──▶ decode64() ──▶ JSON ──▶ apply config  │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

## Configuração de Ambiente

### Variáveis de Ambiente (Backend):

```bash
# /opt/rdgen/rdgen-real/backend/.env
PORT=4000
GITHUB_TOKEN=ghp_xxx           # Token GitHub com permissão actions
GITHUB_OWNER=mjrolin
GITHUB_REPO=rdgen
GEN_URL=https://rdgen.exemplo.com
```

### Serviços Systemd:

```bash
# Backend
/etc/systemd/system/rdgen-backend.service

# Frontend (se usando PM2 ou similar)
pm2 start npm --name "rdgen-frontend" -- start
```

### Nginx:

```nginx
# /etc/nginx/sites-enabled/rdgen

server {
    listen 443 ssl;
    server_name rdgen.exemplo.com;

    # Frontend
    location / {
        proxy_pass http://localhost:3000;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:4000;
    }
}
```

## Repositórios

| Repo | Descrição |
|------|-----------|
| `mjrolin/rdgen` | Workflows e patches |
| `mjrolin/rustdesk` | Fork do RustDesk (source) |
| `nextcoreti/rdgen` | Repositório oficial |
| `rustdesk/rustdesk` | RustDesk oficial |

## Troubleshooting

### Build não aplica customizações
- Verificar se `custom_.txt` contém base64 (não JSON puro)
- Verificar logs do step "allow custom.txt"
- Verificar se `allowCustom.py` rodou com sucesso

### Build falha no checkout
- Verificar se tag existe em `mjrolin/rustdesk`
- Sincronizar fork com upstream se necessário

### Artefatos não chegam no backend
- Verificar `GEN_URL` no workflow
- Verificar se `/api/save_custom_client` está acessível
- Verificar token de autenticação

### Ícone/Logo não aplicado
- Verificar se imagem foi enviada em base64
- Verificar logs do step "icon stuff" / "logo stuff"
- Verificar se ImageMagick está funcionando
