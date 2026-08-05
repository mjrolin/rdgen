# Correção do custom_.txt - Documentação Técnica

**Data:** 2026-01-10
**Versão RustDesk:** 1.4.5
**Status:** Resolvido

## Resumo do Problema

Os clientes RustDesk compilados pelo RDGen não estavam aplicando as customizações (senhas, permissões, configurações de segurança, etc.) definidas no frontend.

## Causa Raiz

O RustDesk lê o arquivo `custom_.txt` através da função `read_custom_client()` em `src/common.rs`:

```rust
pub fn read_custom_client(config: &str) {
    let Ok(data) = decode64(config) else {  // ← ESPERA BASE64!
        log::error!("Failed to decode custom client config");
        return;
    };
    // ... verificação de assinatura (removida pelo allowCustom.py) ...
    let Ok(mut data) = serde_json::from_slice(...)  // ← Depois parse JSON
```

### Fluxo esperado pelo RustDesk:
1. Lê conteúdo do `custom_.txt`
2. **Decodifica de base64** (`decode64()`)
3. Parse do JSON resultante
4. Aplica configurações

### O que estava acontecendo (ERRADO):
```
Backend           →    Workflow         →    custom_.txt    →    RustDesk
JSON puro              base64 -d             JSON puro           decode64() FALHA!
                       (decodifica)
```

O backend enviava JSON puro, o workflow decodificava (resultando em JSON puro no arquivo), mas o RustDesk esperava base64.

## Solução Implementada

### Fluxo correto:
```
Backend           →    Workflow         →    custom_.txt    →    RustDesk
JSON → base64          cat                   string base64       decode64() → JSON ✓
                       (passa direto)
```

### Arquivos Modificados

#### 1. Backend: `/opt/rdgen/rdgen-real/backend/src/utils/configBuilder.ts`

```typescript
// ANTES (errado):
const customJson = JSON.stringify(custom);
// ...
custom: customJson,

// DEPOIS (correto):
const customBase64 = Buffer.from(JSON.stringify(custom)).toString('base64');
// ...
custom: customBase64,
```

#### 2. Workflow: `.github/workflows/generator-windows.yml`

```yaml
# ANTES (errado - decodificava):
- name: Create custom_.txt file
  run: |
    echo -n "${{ inputs.custom }}" | base64 -d > ./rustdesk/custom_.txt

# DEPOIS (correto - passa direto):
- name: Create custom_.txt file
  run: |
    echo -n "${{ inputs.custom }}" | cat > ./rustdesk/custom_.txt
```

## Estrutura do custom_.txt

### Formato do JSON (antes de codificar em base64):

```json
{
  "override-settings": {
    "peer-tab-visible": [false, false, false, true, true],
    "access-mode": "custom",
    "enable-keyboard": "Y",
    "enable-clipboard": "Y",
    ...
  },
  "default-settings": {
    ...
  },
  "password": "senha_permanente",
  "enable-lan-discovery": "Y",
  "allow-auto-disconnect": "N",
  "conn-type": "incoming",
  "disable-installation": "Y",
  "disable-settings": "Y",
  "app-name": "MeuApp"
}
```

### Campos principais:

| Campo | Descrição | Valores |
|-------|-----------|---------|
| `password` | Senha permanente | string |
| `conn-type` | Direção de conexão | `incoming`, `outgoing` |
| `disable-installation` | Desabilita instalação | `Y`/`N` |
| `disable-settings` | Desabilita configurações | `Y`/`N` |
| `app-name` | Nome customizado do app | string |
| `enable-lan-discovery` | Descoberta LAN | `Y`/`N` |
| `allow-auto-disconnect` | Desconexão automática | `Y`/`N` |

### Campos em `override-settings` / `default-settings`:

| Campo | Descrição |
|-------|-----------|
| `access-mode` | `full`, `view`, `custom` |
| `enable-keyboard` | Permite teclado |
| `enable-clipboard` | Permite clipboard |
| `enable-file-transfer` | Permite transferência de arquivos |
| `enable-audio` | Permite áudio |
| `enable-tunnel` | Permite túnel TCP |
| `enable-remote-restart` | Permite reinício remoto |
| `enable-record-session` | Permite gravação |
| `enable-block-input` | Permite bloquear input |
| `allow-remote-config-modification` | Permite modificar config |
| `direct-server` | Permite IP direto |
| `verification-method` | `use-permanent-password`, `use-both-passwords` |
| `approve-mode` | `password`, `click`, `password-click` |
| `allow-hide-cm` | Permite esconder janela de conexão |
| `allow-remove-wallpaper` | Permite remover wallpaper |
| `enable-remote-printer` | Permite impressora remota |
| `enable-camera` | Permite câmera |
| `enable-terminal` | Permite terminal |
| `peer-tab-visible` | Array de 5 booleans [Recent, Favorites, Discovered, AddressBook, MyGroup] |

## Patches Aplicados

### allowCustom.py
- **Origem:** `https://raw.githubusercontent.com/bryangerlach/rdgen/master/.github/patches/allowCustom.py`
- **Função:** Remove a verificação de assinatura criptográfica do `custom_.txt`
- **Modifica:** `src/common.rs`
- **Também:** Renomeia `custom.txt` → `custom_.txt` (compatibilidade com driver de impressora)

### Código removido pelo patch:
```rust
const KEY: &str = "5Qbwsde3unUcJBtrx9ZkvUmwFNoExHzpryHuPUdqlWM=";
let Some(pk) = get_rs_pk(KEY) else {
    log::error!("Failed to parse public key of custom client");
    return;
};
let Ok(data) = sign::verify(&data, &pk) else {
    log::error!("Failed to dec custom client config");
    return;
};
```

## Histórico de Mudanças

| Data | Mudança | Motivo |
|------|---------|--------|
| 2025-11-25 | Driver impressora removido | Bloqueava `custom.txt` |
| 2025-12-10 | `custom.txt` → `custom_.txt` | Permitir driver + custom |
| 2026-01-10 | Corrigido encoding base64 | Customizações não aplicavam |

## Comparação com Bryan's RDGen

| Componente | Bryan | Nosso (após fix) |
|------------|-------|------------------|
| Backend encoding | base64 | base64 ✓ |
| Workflow | `cat` | `cat` ✓ |
| allowCustom.py | Do repo dele | Do repo dele ✓ |
| Repositório RustDesk | `rustdesk/rustdesk` | `mjrolin/rustdesk` |

## Verificação

Para verificar se o fix está funcionando, cheque os logs do GitHub Actions:

1. Step "Create custom_.txt file" deve mostrar uma string base64 longa
2. O cliente compilado deve ter as configurações aplicadas

### Exemplo de string base64 válida:
```
eyJvdmVycmlkZS1zZXR0aW5ncyI6eyJwZWVyLXRhYi12aXNpYmxlIjpbZmFsc2UsZmFsc2UsZmFsc2UsdHJ1ZSx0cnVlXX0...
```

### Decodificando para verificar:
```bash
echo "STRING_BASE64" | base64 -d
# Deve mostrar JSON válido
```

## Arquivos Relevantes

```
/opt/rdgen/rdgen-real/
├── backend/
│   └── src/
│       └── utils/
│           └── configBuilder.ts    # Gera o JSON e codifica em base64
├── frontend/
│   └── src/
│       └── types/
│           └── index.ts            # Tipos e templates
└── docs/
    └── CUSTOM_TXT_FIX.md          # Esta documentação

/tmp/rdgen-github/
└── .github/
    └── workflows/
        └── generator-windows.yml   # Workflow que escreve custom_.txt
```

## Contato

Para dúvidas ou problemas relacionados, verificar:
1. Logs do GitHub Actions
2. Conteúdo do `custom_.txt` no workflow
3. Comparar com implementação do Bryan: `github.com/bryangerlach/rdgen`
