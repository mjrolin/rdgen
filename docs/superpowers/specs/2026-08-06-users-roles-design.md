# Sistema de Usuários e Permissões — Design

**Data:** 2026-08-06
**Projeto:** rdgen (nextcoreti/rdgen)
**Status:** Aprovado, pendente de implementação

## Contexto

Hoje o rdgen tem autenticação hardcoded no código (`basicAuth.ts`):
dois usuários com senhas em plaintext, sessões em memória, sem
controle de permissões granular. Qualquer usuário logado pode fazer
tudo: criar clientes, gerar builds, gerenciar perfis.

O objetivo é implementar um sistema de usuários com papéis
predefinidos, onde o admin cria contas e atribui papéis, e cada
papel tem permissões específicas sobre o que pode fazer no sistema.

## Modelo de dados

Arquivo: `backend/data/users.json` (permissão 600, diretório 700)

```json
[
  {
    "id": "uuid",
    "username": "admin",
    "passwordHash": "$2b$10$...",
    "name": "Administrador",
    "role": "admin",
    "isActive": true,
    "createdAt": "2026-08-06T12:00:00.000Z",
    "lastLogin": "2026-08-06T12:00:00.000Z"
  }
]
```

## Papéis e permissões

| Papel | clients:read | clients:write | profiles:save | builds:generate | users:manage |
|---|---|---|---|---|---|
| **admin** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **operador** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **construtor** | ✅ | ❌ | ❌ | ✅ | ❌ |
| **visualizador** | ✅ | ❌ | ❌ | ❌ | ❌ |

- `clients:read` — ver lista de clientes, perfis, versões
- `clients:write` — criar/editar/excluir clientes e perfis
- `profiles:save` — salvar perfil (botão Salvar Perfil)
- `builds:generate` — gerar build (botão Gerar Build)
- `users:manage` — criar/editar/desativar usuários

## Segurança

- Senhas hasheadas com **bcrypt** (10 rounds), nunca em plaintext.
- Sessões em memória com token de 64 chars aleatórios, expiração 24h.
- O admin inicial é criado no primeiro startup se `users.json` não existir,
  usando `ADMIN_USERNAME` e `ADMIN_PASSWORD` do `.env`.
- Usuário não pode desativar a si mesmo.
- Usuário desativado perde sessão imediatamente.

## API

### Autenticação (públicas — dentro do fluxo de login existente)

| Método | Rota | Ação |
|---|---|---|
| POST | `/api/auth/login` | Login com username + password → retorna token + role + name + permissions |
| POST | `/api/auth/logout` | Invalida sessão |
| GET | `/api/auth/check` | Verifica sessão → retorna dados do usuário (já existe) |

### Gestão de usuários (admin only)

| Método | Rota | Ação |
|---|---|---|
| GET | `/api/admin/users` | Lista todos os usuários (sem hash) |
| POST | `/api/admin/users` | Cria usuário `{username, password, name, role}` |
| PATCH | `/api/admin/users/:id` | Edita `{name, role, isActive}` ou `{password}` |
| DELETE | `/api/admin/users/:id` | Desativa usuário (isActive=false) |

### Proteção de rotas existentes

As rotas existentes de clientes/perfis continuam atrás do `basicAuth`.
O `basicAuth` agora valida contra `users.json` em vez de hardcoded,
e anexa o objeto `user` (com `role`) ao `req`.

Middleware novo `requirePermission(permission)` verifica se o papel
do usuário tem a permissão necessária.

## Fluxo de login

1. Usuário digita username + password na página `/login`.
2. Frontend envia `POST /api/auth/login` com `{username, password}`.
3. Backend valida bcrypt hash, cria sessão, retorna `{token, user: {name, username, role, permissions}}`.
4. Frontend salva token + dados do usuário no localStorage.
5. Redireciona para `/` (ou `/admin` se admin).

## Fluxo de gestão de usuários (admin)

1. Admin acessa `/admin/usuarios`.
2. Vê tabela com todos os usuários: Nome, Username, Papel, Status, Ações.
3. Botão "Novo Usuário" → modal com Nome, Username, Senha, Papel (dropdown).
4. Pode editar papel, desativar/ativar, resetar senha.

## Arquivos a modificar

### Backend

| Arquivo | Mudança |
|---|---|
| `backend/src/services/userStore.ts` | **Novo** — CRUD de usuários em JSON, bcrypt hashing |
| `backend/src/middleware/basicAuth.ts` | Validar contra userStore em vez de hardcoded |
| `backend/src/middleware/permissions.ts` | **Novo** — `requirePermission(p)` middleware |
| `backend/src/routes/api.ts` | Adicionar rotas de gestão de usuários |
| `backend/src/routes/clients.ts` | Adicionar `requirePermission` nas rotas |
| `backend/src/index.ts` | Criar admin inicial no startup se necessário |
| `backend/package.json` | Adicionar `bcrypt` como dependência |

### Frontend

| Arquivo | Mudança |
|---|---|
| `frontend/src/lib/auth.ts` | Salvar role/permissions do usuário no localStorage |
| `frontend/src/lib/permissions.ts` | **Novo** — helpers `canEdit()`, `canBuild()`, `canSave()`, `isAdmin()` |
| `frontend/src/app/login/page.tsx` | Adaptar para receber role/permissions no login |
| `frontend/src/app/page.tsx` | Esconder botões baseado em permissões |
| `frontend/src/app/clientes/page.tsx` | Esconder ações baseado em permissões |
| `frontend/src/app/admin/usuarios/page.tsx` | **Novo** — página de gestão de usuários |
| `frontend/src/components/AuthGuard.tsx` | Adicionar verificação de permissão |

## Fora de escopo

- Auto-cadastro de usuários.
- Recuperação de senha por email.
- Auditoria/logs de ações por usuário.
- Token refresh automático (sessão expira em 24h, precisa re-login).
