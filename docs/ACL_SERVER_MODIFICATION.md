# Modificacao do rustdesk-server para ACL

**Data:** 2026-01-11
**Fork base:** https://github.com/lejianwen/rustdesk-server
**Status:** Plano de Implementacao

## 1. Problema Identificado

### Estrutura atual do PunchHoleRequest

```protobuf
message PunchHoleRequest {
  string id = 1;              // ID do DESTINO (para quem conectar)
  NatType nat_type = 2;
  string licence_key = 3;
  ConnType conn_type = 4;
  string token = 5;
  string version = 6;
  // ... outros campos
}
```

**Problema:** NAO existe campo `from_id` (quem esta pedindo a conexao).

O servidor so sabe:
- `ph.id` = ID do destino (Host B)
- `addr` = SocketAddr do requisitante (IP:porta de A)
- **NAO SABE** = ID do requisitante (Host A)

## 2. Solucoes Possiveis

### Opcao A: Reverse Lookup (Recomendada)

Adicionar mapeamento reverso no servidor: `SocketAddr → PeerID`

**Vantagens:**
- Nao modifica protocolo
- Nao requer mudancas no cliente
- Compativel com clientes existentes

**Desvantagens:**
- Requer memoria adicional no servidor
- Precisa manter sincronizado com registros

### Opcao B: Modificar Protocolo

Adicionar campo `from_id` no PunchHoleRequest.

**Vantagens:**
- Solucao limpa e explicita

**Desvantagens:**
- Requer modificar hbb_common (protobuf)
- Requer recompilar TODOS os clientes
- Quebra compatibilidade retroativa

### Opcao C: Usar Token para Identificacao

O campo `token` ja existe - usar para enviar ID assinado.

**Vantagens:**
- Nao modifica protocolo
- Pode incluir validacao JWT

**Desvantagens:**
- Requer modificar cliente para enviar token
- Complexidade adicional

## 3. Implementacao Opcao A (Recomendada)

### 3.1. Modificar peer.rs

Adicionar mapa reverso de SocketAddr para PeerID:

```rust
// peer.rs - Adicionar

use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;

// Mapa reverso: SocketAddr -> PeerID
lazy_static::lazy_static! {
    pub(crate) static ref ADDR_TO_PEER: RwLock<HashMap<SocketAddr, String>> =
        RwLock::new(HashMap::new());
}

impl PeerMap {
    // Adicionar metodo para registrar mapeamento reverso
    pub async fn register_addr_mapping(&self, addr: SocketAddr, id: String) {
        let mut map = ADDR_TO_PEER.write().await;
        map.insert(addr, id);
    }

    // Adicionar metodo para lookup reverso
    pub async fn get_id_by_addr(&self, addr: &SocketAddr) -> Option<String> {
        let map = ADDR_TO_PEER.read().await;
        map.get(addr).cloned()
    }

    // Adicionar metodo para limpar mapeamento
    pub async fn remove_addr_mapping(&self, addr: &SocketAddr) {
        let mut map = ADDR_TO_PEER.write().await;
        map.remove(addr);
    }

    // Modificar o metodo update_pk existente para registrar mapeamento
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        // ... outros params
    ) -> register_pk_response::Result {
        // Codigo existente...

        // ADICIONAR: Registrar mapeamento reverso
        self.register_addr_mapping(addr, id.clone()).await;

        // Resto do codigo existente...
    }
}
```

### 3.2. Adicionar Modulo ACL

Criar novo arquivo `src/acl.rs`:

```rust
// acl.rs - Novo arquivo

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::RwLock;
use std::collections::HashMap;
use std::time::Instant;

// Cache de decisoes ACL (evita chamadas repetidas a API)
lazy_static::lazy_static! {
    static ref ACL_CACHE: RwLock<HashMap<(String, String), (bool, Instant)>> =
        RwLock::new(HashMap::new());
}

const ACL_CACHE_TTL: Duration = Duration::from_secs(60); // Cache por 1 minuto
const ACL_API_TIMEOUT: Duration = Duration::from_secs(2); // Timeout de 2s

#[derive(Serialize)]
struct AclCheckRequest {
    from_peer: String,
    to_peer: String,
}

#[derive(Deserialize)]
struct AclCheckResponse {
    allowed: bool,
    #[serde(default)]
    reason: String,
}

pub struct AclChecker {
    client: Client,
    api_url: String,
    enabled: bool,
    fail_open: bool, // Se API falhar, permitir ou negar?
}

impl AclChecker {
    pub fn new() -> Self {
        let api_url = std::env::var("ACL_API_URL")
            .unwrap_or_default();
        let enabled = !api_url.is_empty();
        let fail_open = std::env::var("ACL_FAIL_OPEN")
            .map(|v| v == "Y" || v == "true" || v == "1")
            .unwrap_or(true); // Default: fail-open

        Self {
            client: Client::builder()
                .timeout(ACL_API_TIMEOUT)
                .build()
                .unwrap(),
            api_url,
            enabled,
            fail_open,
        }
    }

    pub async fn check(&self, from_peer: &str, to_peer: &str) -> bool {
        if !self.enabled {
            return true; // ACL desabilitado = permitir tudo
        }

        // Verificar cache primeiro
        if let Some(cached) = self.check_cache(from_peer, to_peer).await {
            return cached;
        }

        // Consultar API
        match self.query_api(from_peer, to_peer).await {
            Ok(allowed) => {
                self.update_cache(from_peer, to_peer, allowed).await;
                allowed
            }
            Err(e) => {
                log::warn!("ACL API error: {}, fail_open={}", e, self.fail_open);
                self.fail_open
            }
        }
    }

    async fn check_cache(&self, from_peer: &str, to_peer: &str) -> Option<bool> {
        let cache = ACL_CACHE.read().await;
        let key = (from_peer.to_string(), to_peer.to_string());

        if let Some((allowed, timestamp)) = cache.get(&key) {
            if timestamp.elapsed() < ACL_CACHE_TTL {
                return Some(*allowed);
            }
        }
        None
    }

    async fn update_cache(&self, from_peer: &str, to_peer: &str, allowed: bool) {
        let mut cache = ACL_CACHE.write().await;
        let key = (from_peer.to_string(), to_peer.to_string());
        cache.insert(key, (allowed, Instant::now()));
    }

    async fn query_api(&self, from_peer: &str, to_peer: &str) -> Result<bool, String> {
        let request = AclCheckRequest {
            from_peer: from_peer.to_string(),
            to_peer: to_peer.to_string(),
        };

        let response = self.client
            .post(&format!("{}/api/acl/check", self.api_url))
            .json(&request)
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("API returned status: {}", response.status()));
        }

        let acl_response: AclCheckResponse = response
            .json()
            .await
            .map_err(|e| format!("Parse failed: {}", e))?;

        if !acl_response.allowed {
            log::info!(
                "ACL denied: {} -> {} (reason: {})",
                from_peer, to_peer, acl_response.reason
            );
        }

        Ok(acl_response.allowed)
    }
}

// Instancia global
lazy_static::lazy_static! {
    pub static ref ACL: AclChecker = AclChecker::new();
}
```

### 3.3. Modificar rendezvous_server.rs

Integrar ACL na funcao `handle_punch_hole_request`:

```rust
// rendezvous_server.rs - Modificar

use crate::acl::ACL;
use crate::peer::ADDR_TO_PEER;

#[inline]
async fn handle_punch_hole_request(
    &mut self,
    addr: SocketAddr,
    ph: PunchHoleRequest,
    key: &str,
    ws: bool,
) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
    // Validacao de license key existente
    if !key.is_empty() && ph.licence_key != key {
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_punch_hole_response(PunchHoleResponse {
            failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
            ..Default::default()
        });
        return Ok((msg_out, None));
    }

    let target_id = ph.id.clone();

    // ========== NOVO: ACL CHECK ==========
    // Obter ID do requisitante pelo SocketAddr
    let from_id = {
        let map = ADDR_TO_PEER.read().await;
        map.get(&addr).cloned()
    };

    if let Some(from_peer) = &from_id {
        // Verificar ACL
        if !ACL.check(from_peer, &target_id).await {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                // Usar LICENSE_MISMATCH como erro generico
                // ou adicionar novo tipo de erro ACL_DENIED
                ..Default::default()
            });
            log::info!("ACL denied connection: {} -> {}", from_peer, target_id);
            return Ok((msg_out, None));
        }
    } else {
        // Requisitante nao registrado - decidir politica
        // Opcao 1: Negar (mais seguro)
        // Opcao 2: Permitir (compatibilidade)
        log::warn!("Unknown requester from {}, allowing by default", addr);
    }
    // ========== FIM ACL CHECK ==========

    // Resto do codigo existente...
    if let Some(peer) = self.pm.get(&target_id).await {
        // ... codigo existente de punch hole
    }
}
```

### 3.4. Modificar lib.rs

Adicionar modulo ACL:

```rust
// lib.rs - Adicionar

mod acl;
pub mod rendezvous_server;
pub mod common;
pub mod database;
pub mod peer;
pub mod version;
```

### 3.5. Atualizar Cargo.toml

Adicionar dependencias necessarias:

```toml
[dependencies]
# Dependencias existentes...

# Adicionar para ACL
reqwest = { version = "0.11", features = ["json"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

## 4. Endpoint API no rustdesk-api-custom

### 4.1. Novo modelo ACL

Criar `model/acl.go`:

```go
package model

type AclRule struct {
    IdModel
    FromPeer    string `json:"from_peer" gorm:"index;not null"`    // ID que quer conectar
    ToPeer      string `json:"to_peer" gorm:"index;not null"`      // ID destino (* = todos)
    Allowed     bool   `json:"allowed" gorm:"default:true"`         // Permitir ou negar
    Priority    int    `json:"priority" gorm:"default:0"`           // Regras com maior prioridade primeiro
    Description string `json:"description"`
    TimeModel
}

type AclRuleList struct {
    Rules []*AclRule `json:"list"`
    Pagination
}

// Resultado da verificacao
type AclCheckResult struct {
    Allowed bool   `json:"allowed"`
    Reason  string `json:"reason"`
}
```

### 4.2. Service ACL

Criar `service/acl.go`:

```go
package service

import (
    "github.com/lejianwen/rustdesk-api/v2/model"
)

type AclService struct{}

// Check verifica se from_peer pode conectar a to_peer
func (s *AclService) Check(fromPeer, toPeer string) *model.AclCheckResult {
    result := &model.AclCheckResult{Allowed: true, Reason: "default allow"}

    // Buscar regras que se aplicam (ordenadas por prioridade)
    var rules []model.AclRule
    DB.Where(
        "(from_peer = ? OR from_peer = '*') AND (to_peer = ? OR to_peer = '*')",
        fromPeer, toPeer,
    ).Order("priority DESC").Find(&rules)

    // Aplicar primeira regra que match
    for _, rule := range rules {
        if s.matchRule(&rule, fromPeer, toPeer) {
            result.Allowed = rule.Allowed
            if rule.Allowed {
                result.Reason = "allowed by rule: " + rule.Description
            } else {
                result.Reason = "denied by rule: " + rule.Description
            }
            break
        }
    }

    return result
}

func (s *AclService) matchRule(rule *model.AclRule, fromPeer, toPeer string) bool {
    fromMatch := rule.FromPeer == "*" || rule.FromPeer == fromPeer
    toMatch := rule.ToPeer == "*" || rule.ToPeer == toPeer
    return fromMatch && toMatch
}

// CRUD methods
func (s *AclService) Create(rule *model.AclRule) error {
    return DB.Create(rule).Error
}

func (s *AclService) Update(rule *model.AclRule) error {
    return DB.Model(rule).Updates(rule).Error
}

func (s *AclService) Delete(id uint) error {
    return DB.Delete(&model.AclRule{}, id).Error
}

func (s *AclService) List(page, pageSize uint) *model.AclRuleList {
    result := &model.AclRuleList{}
    tx := DB.Model(&model.AclRule{})
    tx.Count(&result.Total)
    tx.Scopes(Paginate(page, pageSize)).Order("priority DESC").Find(&result.Rules)
    return result
}
```

### 4.3. Controller API

Criar `http/controller/api/acl.go`:

```go
package api

import (
    "github.com/gin-gonic/gin"
    "github.com/lejianwen/rustdesk-api/v2/http/response"
    "github.com/lejianwen/rustdesk-api/v2/service"
)

type Acl struct{}

type AclCheckRequest struct {
    FromPeer string `json:"from_peer" binding:"required"`
    ToPeer   string `json:"to_peer" binding:"required"`
}

// Check verifica se conexao e permitida
// @Tags ACL
// @Summary Verificar ACL
// @Description Verifica se from_peer pode conectar a to_peer
// @Accept json
// @Produce json
// @Param body body AclCheckRequest true "Request"
// @Success 200 {object} model.AclCheckResult
// @Router /api/acl/check [post]
func (a *Acl) Check(c *gin.Context) {
    req := &AclCheckRequest{}
    if err := c.ShouldBindJSON(req); err != nil {
        response.Error(c, "ParamsError: "+err.Error())
        return
    }

    result := service.AllService.AclService.Check(req.FromPeer, req.ToPeer)
    c.JSON(200, result)
}
```

### 4.4. Registrar rota

Modificar `http/router/api.go`:

```go
// Em ApiInit()
{
    acl := &api.Acl{}
    frg.POST("/acl/check", acl.Check)
}
```

### 4.5. Admin endpoints

Criar `http/controller/admin/acl.go` para gerenciar regras via painel.

## 5. Configuracao

### Variaveis de ambiente do servidor

```bash
# Ativar ACL
ACL_API_URL=https://rustdesk-api.example.com

# Comportamento quando API falha
ACL_FAIL_OPEN=Y    # Y = permitir se API offline (default)
                   # N = negar se API offline
```

### Exemplos de regras ACL

```sql
-- Regra 1: Suporte pode conectar em qualquer host
INSERT INTO acl_rules (from_peer, to_peer, allowed, priority, description)
VALUES ('123456789', '*', true, 100, 'Suporte full access');

-- Regra 2: Host especifico so aceita do suporte
INSERT INTO acl_rules (from_peer, to_peer, allowed, priority, description)
VALUES ('*', '987654321', false, 50, 'Host locked - deny all');

INSERT INTO acl_rules (from_peer, to_peer, allowed, priority, description)
VALUES ('123456789', '987654321', true, 60, 'Allow suporte to locked host');

-- Regra 3: Negar peer especifico (blacklist)
INSERT INTO acl_rules (from_peer, to_peer, allowed, priority, description)
VALUES ('666666666', '*', false, 200, 'Banned user');
```

## 6. Fluxo Completo

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         FLUXO COM ACL                                     │
└──────────────────────────────────────────────────────────────────────────┘

   PC Admin (ID: 123)                                  Host (ID: 456)
         │                                                   │
         │  1. RegisterPk (ao iniciar)                       │
         │─────────────────────────────────────────────────►│
         │                                                   │
         │                        ┌──────────────┐           │
         │                        │  hbbs        │           │
         │                        │              │           │
         │  2. PunchHoleRequest   │ Registra:    │           │
         │     id=456             │ IP:Port→123  │           │
         │─────────────────────────►             │           │
         │                        │              │           │
         │                        │ 3. Lookup:   │           │
         │                        │    from=123  │           │
         │                        │    to=456    │           │
         │                        │              │           │
         │                        │     ┌────────▼────────┐  │
         │                        │     │ rustdesk-api    │  │
         │                        │     │ POST /acl/check │  │
         │                        │     │ {from:123,to:456}│ │
         │                        │     └────────┬────────┘  │
         │                        │              │           │
         │                        │ 4. Response: │           │
         │                        │    allowed:true          │
         │                        │              │           │
         │  5. PunchHoleResponse  │◄─────────────┘           │
         │     (com addr de 456)  │                          │
         │◄────────────────────────                          │
         │                                                   │
         │  6. Conexao direta ou via relay                   │
         │───────────────────────────────────────────────────►
         │                                                   │
```

## 7. Riscos e Mitigacoes

| Risco | Impacto | Mitigacao |
|-------|---------|-----------|
| API offline | Conexoes bloqueadas ou liberadas | Cache + fail-open/closed config |
| Latencia | Atraso na conexao | Cache de 60s + timeout 2s |
| Mapeamento incorreto | ACL falha | Logging + fallback |
| Memoria excessiva | Servidor lento | Limitar tamanho do mapa reverso |
| Desincronizacao | Mapa desatualizado | TTL + cleanup periodico |

## 8. Estimativa de Esforco

| Tarefa | Horas |
|--------|-------|
| Modificar peer.rs (reverse lookup) | 4h |
| Criar modulo acl.rs | 8h |
| Modificar rendezvous_server.rs | 4h |
| Criar endpoint API (Go) | 6h |
| Criar painel admin ACL | 8h |
| Testes | 8h |
| Documentacao | 4h |
| **Total** | **42h** |

## 9. Alternativa: Usar Campo Token

Se nao quiser modificar o servidor, pode usar o campo `token` do PunchHoleRequest:

1. Cliente envia: `token = JWT(from_id, timestamp, signature)`
2. Servidor decodifica JWT para obter `from_id`
3. Verifica ACL normalmente

**Vantagem:** Nao precisa mapa reverso
**Desvantagem:** Precisa modificar cliente para enviar token

## 10. Proximos Passos

1. **Fork o repositorio** lejianwen/rustdesk-server
2. **Implementar reverse lookup** em peer.rs
3. **Criar modulo ACL** em acl.rs
4. **Integrar no rendezvous_server.rs**
5. **Compilar e testar** localmente
6. **Criar endpoint API** no rustdesk-api-custom
7. **Testar fluxo completo**
8. **Deploy em producao**

## 11. Comandos de Build

```bash
# Clonar fork
git clone https://github.com/SEU_USUARIO/rustdesk-server
cd rustdesk-server

# Aplicar modificacoes
# ... editar arquivos conforme documentado acima ...

# Compilar
cargo build --release

# Binarios gerados em target/release/
# - hbbs
# - hbbr
# - rustdesk-utils

# Rodar com ACL
ACL_API_URL=https://api.example.com ./target/release/hbbs -r relay.example.com
```
