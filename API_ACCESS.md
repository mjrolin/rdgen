# 🔗 Acesso à Documentação da API

## 📍 URLs de Acesso

### Documentação Interativa (Swagger UI)
```
https://rdgen.nextcoreti.com.br/swagger-api
```
Interface visual com todos os endpoints, parâmetros e exemplos interativos.

### Especificação OpenAPI (JSON)
```
https://rdgen.nextcoreti.com.br/swagger.json
```
Arquivo JSON com a especificação completa da API (OpenAPI 3.0).

### Health Check
```
https://rdgen.nextcoreti.com.br/api/health
```
Verifica se a API está funcionando.

---

## 🚀 Versões Disponíveis do RustDesk

As seguintes versões do RustDesk estão disponíveis para build:

- **nightly** (versão de desenvolvimento)
- **1.4.5** (mais recente)
- 1.4.4
- 1.4.3
- 1.4.2
- 1.4.1
- 1.4.0
- 1.3.9
- 1.3.8
- 1.3.7
- 1.3.6
- 1.3.5
- 1.3.4
- 1.3.3
- 1.3.2
- 1.3.1
- 1.3.0
- 1.2.7
- 1.2.6
- 1.2.5
- 1.2.3-1

---

## ⚡ Quick Start

### 1. Testar a API
```bash
curl https://rdgen.nextcoreti.com.br/api/health
```

### 2. Iniciar um Build
```bash
curl -X POST https://rdgen.nextcoreti.com.br/api/build \
  -H "Content-Type: application/json" \
  -d '{
    "configName": "Meu Cliente",
    "platform": "windows",
    "version": "1.4.5",
    "host": "rustdesk.example.com",
    "key": "sua_chave_publica",
    "apiServer": "https://api.example.com"
  }'
```

### 3. Verificar Status
```bash
curl https://rdgen.nextcoreti.com.br/api/status/{jobId}
```

---

## 🔑 Autenticação

### Opção 1: Sem autenticação (acesso básico)
Qualquer pessoa pode usar os endpoints públicos.

### Opção 2: API Key (multi-tenant)
Para uso em produção, solicite uma API key:

```bash
curl -X POST https://rdgen.nextcoreti.com.br/api/build \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sua_api_key_aqui" \
  -d '{...}'
```

### Opção 3: Session Token (painel web)
Para acesso ao painel:

```bash
# Login
curl -X POST https://rdgen.nextcoreti.com.br/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "senha"
  }'

# Usar token nas requisições
curl https://rdgen.nextcoreti.com.br/api/jobs \
  -H "X-Session-Token: token_recebido"
```

---

## 🎨 Novos Recursos - Display Settings

A partir de agora você pode configurar qualidade de imagem e performance:

```json
{
  "configName": "Cliente Alta Qualidade",
  "platform": "windows",
  "version": "1.4.5",

  // Configurações de Display (NOVO!)
  "customImageQuality": 80,
  "codecPreference": "vp9",
  "enableHwCodec": true,
  "fps": 30,
  "displayMode": "adaptive",

  // Outras configurações...
  "host": "rustdesk.example.com",
  "key": "..."
}
```

### Parâmetros de Display

| Campo | Tipo | Valores | Descrição |
|-------|------|---------|-----------|
| `customImageQuality` | number | 0-100 | Qualidade da imagem (padrão: 50) |
| `codecPreference` | string | vp9, vp8, h264, h265, av1 | Codec de vídeo (padrão: vp9) |
| `enableHwCodec` | boolean | true/false | Usar GPU para encoding (padrão: true) |
| `fps` | number | 15, 30, 60 | Frames por segundo (padrão: 30) |
| `displayMode` | string | adaptive, original, fit | Modo de exibição (padrão: adaptive) |

### Recomendações

- **VP9**: Melhor qualidade com menor uso de banda
- **H264**: Compatibilidade universal
- **H265**: Alta compressão (requer suporte)
- **Hardware Codec**: Melhor performance com GPU
- **FPS 60**: Ideal para trabalhos gráficos/animações
- **FPS 30**: Balanceado para uso geral
- **FPS 15**: Economizar banda

---

## 📦 Plataformas Disponíveis

### Windows
- `windows` - Windows 64-bit (gera .exe e .msi)
- `windows-x86` - Windows 32-bit (gera .exe)

### Linux
- `linux` - Linux (gera .deb, .rpm, .rpm-suse, .appimage, .pkg.tar.zst)

### Android
- `android` - Android (gera .apk)

### macOS
- `macos` - macOS (gera .dmg para x64 e ARM64/M1)

---

## 📊 Status do Build

| Status | Descrição |
|--------|-----------|
| `pending` | Build criado, aguardando processamento |
| `queued` | Na fila do GitHub Actions |
| `in_progress` | Build em andamento (0-100%) |
| `completed` | Build finalizado com sucesso |
| `failed` | Build falhou (ver logs) |
| `cancelled` | Build cancelado pelo usuário |

---

## 🔄 Polling Recomendado

Para acompanhar o progresso de um build:

```javascript
async function waitForBuild(jobId) {
  while (true) {
    const response = await fetch(`https://rdgen.nextcoreti.com.br/api/status/${jobId}`);
    const { data } = await response.json();

    console.log(`Status: ${data.status} (${data.progress}%)`);

    if (['completed', 'failed', 'cancelled'].includes(data.status)) {
      return data;
    }

    // Aguardar 10 segundos antes de consultar novamente
    await new Promise(resolve => setTimeout(resolve, 10000));
  }
}
```

---

## 📞 Suporte

- **Documentação Completa**: [https://rdgen.nextcoreti.com.br/swagger-api](https://rdgen.nextcoreti.com.br/swagger-api)
- **Exemplos de Código**: Ver `INTEGRATION_EXAMPLES.md`
- **Health Check**: [https://rdgen.nextcoreti.com.br/api/health](https://rdgen.nextcoreti.com.br/api/health)

---

## 🎯 Exemplo Completo

```javascript
// 1. Iniciar build
const buildResponse = await fetch('https://rdgen.nextcoreti.com.br/api/build', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    configName: "Cliente Premium",
    platform: "windows",
    version: "1.4.5",
    host: "rustdesk.example.com",
    key: "chave_publica_base64",
    apiServer: "https://api.example.com",

    // Display Settings
    customImageQuality: 80,
    codecPreference: "vp9",
    enableHwCodec: true,
    fps: 30,
    displayMode: "adaptive",

    // Segurança
    permanentPassword: "senha123",
    disableSettings: true,
    connectionDirection: "Incoming"
  })
});

const { data: job } = await buildResponse.json();
console.log(`Build iniciado: ${job.id}`);

// 2. Aguardar conclusão
const finalJob = await waitForBuild(job.id);

// 3. Download
if (finalJob.status === 'completed') {
  const exeUrl = `https://rdgen.nextcoreti.com.br${finalJob.artifactUrl}`;
  const msiUrl = `https://rdgen.nextcoreti.com.br${finalJob.artifactMsiUrl}`;

  console.log('Download EXE:', exeUrl);
  console.log('Download MSI:', msiUrl);
}
```

---

**Última Atualização**: Janeiro 2026
**Versão da API**: 1.0.0
