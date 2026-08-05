# Implementacao de ACL no RustDesk - Analise Tecnica

**Data:** 2026-01-11
**Status:** Levantamento Completo

## 1. Entendimento do Problema

**Objetivo:** Permitir que o ID RustDesk `XYZ` so aceite conexoes do ID `QWE`.

**Exemplo de uso:**
- Hosts de clientes: so podem receber conexao de PCs do suporte
- PCs do suporte: podem conectar a qualquer host autorizado

## 2. Arquitetura Atual do RustDesk

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FLUXO DE CONEXAO                                │
└─────────────────────────────────────────────────────────────────────────┘

   PC Admin (ID: QWE)                    Host Cliente (ID: XYZ)
         │                                      │
         │  1. "Quero conectar ao XYZ"          │
         ▼                                      │
   ┌───────────┐                               │
   │   hbbs    │  2. "XYZ esta em IP:PORT"     │
   │ (ID/Rend) │◄──────────────────────────────┤ heartbeat
   └─────┬─────┘                               │
         │                                      │
         │  3. Tenta conexao direta (hole punch)│
         ├──────────────────────────────────────►
         │                                      │
         │  4. Se falhar, usa relay             │
   ┌─────▼─────┐                               │
   │   hbbr    │◄──────────────────────────────►
   │  (relay)  │     Conexao via relay          │
   └───────────┘                               │
                                                │
         5. LoginRequest (com senha)            │
         ──────────────────────────────────────►│
                                                │
                     6. Verifica senha LOCALMENTE
                     ◄──────────────────────────┤
                                                │
         7. POST /api/audit/conn (fire-and-forget)
         ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┤
                                                ▼
                                          rustdesk-api
                                         (so registra log)
```

## 3. Problema Fundamental

### O rustdesk-api-custom NAO pode bloquear conexoes porque:

| Componente | Funcao | Pode bloquear? |
|------------|--------|----------------|
| hbbs | Rendezvous/ID server | **SIM** - controla quem encontra quem |
| hbbr | Relay server | Parcial - so conexoes via relay |
| RustDesk Client | Recebe conexao | **SIM** - verifica senha localmente |
| rustdesk-api-custom | API/Audit | **NAO** - so recebe notificacao |

### Por que `/api/audit/conn` nao funciona para ACL?

```rust
// src/server/connection.rs:1187-1190
self.post_conn_audit(json!({
    "ip": addr.ip(),
    "action": "new",   // Notifica que conexao JA COMECOU
}));
```

O codigo envia POST e NAO espera resposta. E fire-and-forget.

## 4. Opcoes de Implementacao

### Opcao A: Modificar hbbs (Servidor)

**Complexidade:** MUITO ALTA
**Efetividade:** 100%

```
Fluxo proposto:
1. PC Admin pede ao hbbs: "Onde esta XYZ?"
2. hbbs consulta API: "QWE pode conectar ao XYZ?"
3. Se NAO, hbbs recusa informar a localizacao
4. Conexao bloqueada no nivel de rendezvous
```

**Problemas:**
- hbbs e codigo fechado (binario pre-compilado)
- Requer fork do rustdesk-server (projeto separado)
- Precisa compilar Rust
- Manutencao complexa

### Opcao B: Modificar Cliente RustDesk

**Complexidade:** ALTA
**Efetividade:** 100%

```rust
// Modificar src/server/connection.rs
// Antes de aceitar conexao, consultar API

async fn check_acl(&self, from_peer: &str) -> bool {
    let url = format!("{}/api/acl/check", self.api_server);
    let response = reqwest::post(&url)
        .json(&json!({
            "peer_id": Config::get_id(),
            "from_peer": from_peer,
        }))
        .send()
        .await;

    match response {
        Ok(r) => r.json::<AclResponse>().await.unwrap_or_default().allowed,
        Err(_) => false, // Fail-safe: negar se API offline
    }
}
```

**Problemas:**
- Requer fork do RustDesk
- Cada nova versao precisa merge
- Tempo de build (Flutter + Rust)
- Manutencao continua

### Opcao C: Agente RMM (Seu modelo atual)

**Complexidade:** BAIXA
**Efetividade:** 90%

```
Fluxo:
1. Painel gera URL com token: rustdesk://...?password=TOKEN_CRIPTOGRAFADO
2. Agente RMM intercepta
3. Agente verifica autorizacao com backend
4. Se OK, decodifica senha e abre RustDesk
5. Se NAO, ignora/alerta
```

**Vantagens:**
- Nao precisa modificar RustDesk
- Nao precisa modificar hbbs
- Controle no seu sistema

**Limitacao:**
- Conexao direta ainda e possivel (se alguem souber a senha)
- Depende do agente estar rodando

### Opcao D: Implementar no rustdesk-api-custom + Modificar Audit

**Complexidade:** MEDIA-ALTA
**Efetividade:** 80%

Modificar o cliente para ESPERAR resposta do audit antes de aceitar conexao.

**Arquivos a modificar:**

1. **RustDesk Client** (`src/server/connection.rs`):
```rust
// Mudar de fire-and-forget para sync
async fn check_connection_allowed(&self, from_peer: &str) -> bool {
    let response = self.post_conn_audit_sync(json!({
        "action": "check",
        "from_peer": from_peer,
    })).await;
    response.map(|r| r.allowed).unwrap_or(false)
}
```

2. **rustdesk-api-custom** (`http/controller/api/audit.go`):
```go
func (a *Audit) AuditConn(c *gin.Context) {
    af := &request.AuditConnForm{}
    c.ShouldBindBodyWith(af, binding.JSON)

    if af.Action == "check" {
        // Verificar ACL
        allowed := service.AllService.AclService.Check(af.PeerId, af.FromPeer)
        c.JSON(http.StatusOK, gin.H{"allowed": allowed})
        return
    }
    // ... resto do codigo atual
}
```

3. **Nova tabela/service ACL**:
```go
type AclRule struct {
    IdModel
    PeerId      string `json:"peer_id"`      // Quem recebe conexao
    AllowedPeer string `json:"allowed_peer"` // Quem pode conectar (* = todos)
    TimeModel
}
```

## 5. Estrutura de Dados para ACL

### Modelo Proposto

```sql
CREATE TABLE acl_rules (
    id INTEGER PRIMARY KEY,
    peer_id VARCHAR(50) NOT NULL,        -- ID do host (ex: 1234567890)
    allowed_peer VARCHAR(50) NOT NULL,   -- ID permitido (ex: 0987654321 ou *)
    group_id INTEGER DEFAULT 0,          -- Grupo (opcional)
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX idx_acl_peer ON acl_rules(peer_id);
CREATE INDEX idx_acl_allowed ON acl_rules(allowed_peer);

-- Exemplo: Host 1234567890 so aceita conexao de 0987654321
INSERT INTO acl_rules (peer_id, allowed_peer) VALUES ('1234567890', '0987654321');

-- Exemplo: Host 1111111111 aceita de qualquer um do grupo 5
INSERT INTO acl_rules (peer_id, allowed_peer, group_id) VALUES ('1111111111', '*', 5);
```

### API Endpoints Propostos

| Metodo | Endpoint | Descricao |
|--------|----------|-----------|
| POST | `/api/acl/check` | Verificar se conexao e permitida |
| GET | `/admin/acl/list` | Listar regras |
| POST | `/admin/acl/create` | Criar regra |
| POST | `/admin/acl/update` | Atualizar regra |
| POST | `/admin/acl/delete` | Deletar regra |
| POST | `/admin/acl/batch` | Importar em lote |

## 6. Riscos e Desafios

### Riscos Tecnicos

| Risco | Probabilidade | Impacto | Mitigacao |
|-------|---------------|---------|-----------|
| Fork do RustDesk desatualiza | Alta | Alto | CI/CD para merge automatico |
| API offline bloqueia todos | Media | Alto | Cache local, fail-open/closed config |
| Latencia na verificacao | Media | Medio | Cache, timeout curto |
| Bypass via conexao direta | Alta | Medio | Usar senha dinamica + agente |

### Riscos de Seguranca

| Risco | Descricao | Mitigacao |
|-------|-----------|-----------|
| Replay attack | Token reutilizado | Tokens com expiracao curta |
| Man-in-the-middle | Interceptacao de tokens | HTTPS obrigatorio |
| Brute force | Tentar senhas | Rate limiting + lockout |
| Bypass do agente | Conectar diretamente | Senha dinamica por sessao |

### Desafios de Manutencao

1. **Fork do RustDesk**: Cada nova versao (1.4.5 → 1.4.6) requer merge manual
2. **Compilacao**: Flutter + Rust + dependencias = build complexo
3. **Multi-plataforma**: Windows, Linux, macOS, Android = 4x trabalho
4. **Testes**: Dificil testar todas combinacoes

## 7. Recomendacao

### Para seu caso especifico (RMM existente):

**Opcao C (Agente RMM)** e a melhor escolha porque:

1. Voce ja tem o agente em desenvolvimento
2. Nao precisa manter fork do RustDesk
3. Controle total no seu sistema
4. Senha fica protegida (nunca exposta no browser)

### Fluxo recomendado:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    FLUXO COM AGENTE RMM                                 │
└─────────────────────────────────────────────────────────────────────────┘

   Painel Admin                 Agente RMM              RustDesk Host
        │                          │                         │
        │  1. Clica "Conectar"     │                         │
        │                          │                         │
        │  2. Gera token + URL     │                         │
        │     rustdesk://?password=│                         │
        │     ENCRYPTED_TOKEN      │                         │
        ▼                          │                         │
   ┌────────────┐                  │                         │
   │ PC Admin   │  3. Abre URL     │                         │
   │ (browser)  │─────────────────►│                         │
   └────────────┘                  │                         │
                                   │  4. Agente intercepta   │
                                   │     protocolo rustdesk://│
                                   ▼                         │
                            ┌─────────────┐                  │
                            │ Agente RMM  │                  │
                            │ decodifica  │                  │
                            │ token       │                  │
                            └──────┬──────┘                  │
                                   │                         │
                                   │  5. Abre RustDesk com   │
                                   │     senha real          │
                                   ▼                         │
                            ┌─────────────┐                  │
                            │ RustDesk    │  6. Conecta      │
                            │ Admin       │─────────────────►│
                            └─────────────┘                  │
```

### Se quiser seguranca adicional (futuro):

Combinar Opcao C + Opcao D:
- Agente decodifica token (protege senha)
- API verifica ACL antes de aceitar (dupla verificacao)

## 8. Estimativa de Esforco

| Opcao | Desenvolvimento | Manutencao/Ano | Recomendado? |
|-------|-----------------|----------------|--------------|
| A - Modificar hbbs | 160h+ | 80h+ | Nao |
| B - Modificar Cliente | 80h+ | 40h+ | Talvez |
| C - Agente RMM | 20h | 10h | **SIM** |
| D - API + Cliente | 60h | 30h | Futuro |

## 9. Proximos Passos

Se decidir implementar:

### Fase 1 (Agente RMM - Recomendado)
1. Finalizar agente com decodificacao de token
2. Registrar protocolo `rustdesk://`
3. Testar fluxo completo

### Fase 2 (ACL na API - Opcional)
1. Criar modelo `AclRule` no rustdesk-api-custom
2. Criar endpoints de gerenciamento
3. Integrar com painel admin

### Fase 3 (Cliente Modificado - Opcional/Futuro)
1. Fork do RustDesk
2. Modificar `connection.rs` para consultar ACL
3. Criar pipeline de build
4. Testar multi-plataforma

## 10. Conclusao

**Para bloquear conexoes por ID no RustDesk:**
- NAO e possivel apenas no rustdesk-api-custom (limitacao arquitetural)
- E possivel modificando o cliente RustDesk OU o servidor hbbs
- A solucao mais pratica para seu caso e usar o **Agente RMM** como gateway

O agente funciona como um "proxy de autenticacao" que:
1. Recebe o pedido de conexao
2. Verifica autorizacao no seu backend
3. Libera ou bloqueia a conexao

Isso da 90% da seguranca com 10% do esforco.
