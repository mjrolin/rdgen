# Perfis de cliente criptografados — Design

**Data:** 2026-08-05
**Projeto:** rdgen (nextcoreti/rdgen)
**Status:** Aprovado, pendente de implementação

## Contexto

Hoje cada compilação disparada pelo RDGen grava um registro completo em
`backend/data/jobs.json` (host, key, apiServer, permissões, ícone/logo em
base64, senha permanente etc.), mas não existe o conceito de "cliente"
reutilizável. Para gerar uma nova build para um cliente já atendido antes,
é preciso preencher o formulário do zero, incluindo reupload de ícone/logo.

O objetivo desta feature é permitir salvar, de forma criptografada, a
configuração de cada cliente, com histórico de versões, para que gerar uma
nova build baseada em um cliente existente seja apenas: escolher o cliente,
escolher a versão de referência, ajustar o que for necessário (ex: versão
do RustDesk, nova senha) e gerar — sem reconfigurar tudo do zero.

## Modelo de dados

Um arquivo por cliente em `backend/data/clients/<clientId>.json`:

```json
{
  "id": "uuid",
  "name": "mrnery",
  "host": "rd01.suporte.net.br",
  "createdAt": "2026-08-05T12:00:00.000Z",
  "updatedAt": "2026-08-05T12:00:00.000Z",
  "latestVersionId": "uuid-v3",
  "versions": [
    {
      "versionId": "uuid-v1",
      "createdAt": "2026-08-05T12:00:00.000Z",
      "label": "",
      "iv": "base64...",
      "authTag": "base64...",
      "ciphertext": "base64..."
    }
  ]
}
```

- `name` e `host` ficam em claro apenas para permitir listar clientes sem
  decriptar nada (usado na tela de seleção).
- Todo o restante da configuração (a mesma estrutura de `config` já usada
  em `jobs.json` — permissões, ícone/logo base64, senha permanente, etc.)
  fica exclusivamente dentro do `ciphertext` de cada versão.
- Cada gravação de versão gera um novo `versionId`, `iv` e `authTag` — as
  versões anteriores nunca são sobrescritas nem decrescem em número.

## Criptografia

- **Algoritmo:** AES-256-GCM.
- **Chave:** chave mestra simétrica de 32 bytes, gerada uma única vez e
  armazenada como `CLIENT_PROFILE_KEY` em `backend/.env` — mesmo nível de
  proteção hoje aplicado a `GITHUB_TOKEN` e `ADMIN_SECRET` (arquivo com
  permissão 600).
- **IV:** aleatório (12 bytes) a cada gravação de versão, nunca reutilizado.
- **Integridade:** o `authTag` do GCM é armazenado junto ao `ciphertext` e
  verificado na decriptação — qualquer adulteração ou corrupção do arquivo
  faz a decriptação falhar de forma explícita, em vez de retornar dados
  incorretos silenciosamente.
- **Inicialização:** se `CLIENT_PROFILE_KEY` não estiver definida no
  ambiente, o backend deve recusar iniciar (falha explícita), para evitar
  perfis criados sem uma chave persistida de forma duradoura.
- Arquivos em `backend/data/clients/` são criados com permissão `600`,
  seguindo o mesmo endurecimento já aplicado a `jobs.json`/`apikeys.json`.

## API

Novos endpoints em `backend/src/routes/api.ts` (ou um novo
`backend/src/routes/clients.ts`, seguindo o padrão de separação já usado
no projeto):

| Método | Rota | Ação |
|---|---|---|
| GET | `/api/clients` | Lista clientes: `id`, `name`, `host`, número de versões, `updatedAt`. Não decripta nada. |
| GET | `/api/clients/:id` | Detalhe de um cliente: metadados + lista de versões (`versionId`, `createdAt`, `label`), sem decriptar o conteúdo. |
| GET | `/api/clients/:id/versions/:versionId` | Decripta e retorna a config completa daquela versão — usado para preencher o formulário de build. |
| POST | `/api/clients` | Cria um cliente novo com sua primeira versão, a partir dos dados atuais do formulário. |
| PUT | `/api/clients/:id` | Encripta o estado atual do formulário como uma **nova versão** do cliente existente (não sobrescreve versões anteriores). |
| DELETE | `/api/clients/:id` | Remove o cliente e todas as suas versões. |

Todos os endpoints seguem o mesmo esquema de autenticação já usado pelas
rotas administrativas existentes (sessão do painel / `ADMIN_SECRET`).

## Fluxo de UI (frontend)

1. No topo do formulário de build (`frontend/src/app/page.tsx`), um
   seletor **"Cliente"** lista os clientes salvos
   (nome + host) e uma opção **"Novo Cliente"**.
2. Ao escolher um cliente existente, o frontend busca
   `GET /api/clients/:id/versions/:latestVersionId` e preenche todos os
   campos do formulário com os dados decriptados.
   - O campo de senha permanente (`permanentPassword`) é preenchido mas
     renderizado mascarado (`type="password"`), com um botão "mostrar"
     para revelar em texto claro sob demanda.
3. Um controle de **histórico de versões** (dropdown ou lista) permite
   carregar uma versão anterior daquele cliente no formulário, sem
   disparar build — útil para comparar ou reverter uma alteração.
4. O usuário ajusta o que for necessário (ex: nova versão do RustDesk,
   nova senha permanente, novo ícone).
5. Ao clicar em **"Gerar"**:
   - o build é disparado normalmente (fluxo atual, inalterado);
   - em paralelo, o backend salva automaticamente uma nova versão no
     perfil do cliente (via `PUT /api/clients/:id`) ou cria o cliente
     (via `POST /api/clients`, se a opção era "Novo Cliente") — usando o
     estado final do formulário no momento do disparo.
   - Dessa forma, a configuração mais recente usada em produção fica
     sempre persistida automaticamente, sem passo manual extra de "salvar
     perfil".

## Fora de escopo / limitações conhecidas desta primeira versão

- **Sem migração automática** do histórico já existente em
  `backend/data/jobs.json` para o novo formato de clientes — os perfis
  passam a ser criados a partir da implementação desta feature em diante.
  Builds antigas continuam consultáveis apenas via `jobs.json`, como hoje.
- **Sem rotação de chave mestra** nesta versão: se `CLIENT_PROFILE_KEY` for
  alterada ou perdida, todos os perfis criptografados anteriormente ficam
  inacessíveis (falha de decriptação, sem fallback). `CLIENT_PROFILE_KEY`
  deve ser tratada como segredo permanente, com backup próprio — fora do
  fluxo normal de backups do projeto atualmente em uso.
- Sem exportação/importação de perfis entre servidores nesta versão.
