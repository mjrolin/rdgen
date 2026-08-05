# RDGen - Changelog

## 2026-01-10

### Correção Crítica: custom_.txt encoding

**Problema:** Customizações não eram aplicadas nos clientes compilados.

**Causa:** O backend enviava JSON puro, mas o RustDesk espera base64.

**Solução:**
- Backend agora codifica JSON em base64 antes de enviar
- Workflow usa `cat` para escrever direto (não decodifica)
- RustDesk decodifica base64 em runtime

**Arquivos modificados:**
- `backend/src/utils/configBuilder.ts` - Mudou para base64 encoding
- `.github/workflows/generator-windows.yml` - Mudou de `base64 -d` para `cat`

### Correção: peer-tab-visible array

**Problema:** Array `peer-tab-visible` estava sendo double-encoded como string JSON.

**Causa:** `JSON.stringify()` era chamado no array antes de incluir no objeto.

**Solução:** Removido `JSON.stringify()` - array é incluído diretamente.

**Antes (errado):**
```typescript
custom['override-settings']['peer-tab-visible'] = JSON.stringify(peerTabVisible);
// Resultava em: "peer-tab-visible": "[false,false,false,true,true]" (string!)
```

**Depois (correto):**
```typescript
custom['override-settings']['peer-tab-visible'] = peerTabVisible;
// Resulta em: "peer-tab-visible": [false,false,false,true,true] (array!)
```

### Nova Feature: Templates de Configuração

Adicionados templates predefinidos no frontend:

| Template | Descrição |
|----------|-----------|
| Admin | Controle total, todas permissões habilitadas |
| Host | Apenas recebe conexões, abas limitadas |
| Cliente | Apenas conexões de saída |
| Personalizado | Configuração manual |

**Arquivos adicionados:**
- `frontend/src/components/TemplateSelector.tsx`
- Templates definidos em `frontend/src/types/index.ts`

### Atualização: Suporte a RustDesk 1.4.5

- Workflows atualizados para compilar versão 1.4.5
- Fork `mjrolin/rustdesk` sincronizado com upstream
- Tag 1.4.5 criada no fork

---

## 2025-12-10 (Bryan's RDGen)

### Mudança: custom.txt → custom_.txt

**Problema:** Driver de impressora do RustDesk verificava `custom.txt` e bloqueava funcionamento.

**Solução:** Renomeado para `custom_.txt` via `allowCustom.py`.

---

## 2025-11-25 (Bryan's RDGen)

### Mudança: Driver de impressora removido

**Problema:** Driver de impressora conflitava com `custom.txt`.

**Solução temporária:** Driver removido do build.

**Nota:** Posteriormente revertido quando `custom_.txt` foi implementado.
