# 📘 Exemplos de Integração - RDGen API

## 🔗 Documentação Completa
Acesse: **https://rdgen.nextcoreti.com.br/api-docs**

---

## 🚀 Exemplo 1: Iniciar Build de Cliente RustDesk

### JavaScript/Node.js
```javascript
const axios = require('axios');

const config = {
  // Obrigatórios
  configName: "Cliente Empresa XYZ",
  platform: "windows",
  version: "1.4.5",

  // Servidor RustDesk
  host: "rustdesk.example.com",
  key: "sua_chave_publica_aqui",
  apiServer: "https://api.example.com",

  // Personalização
  appName: "RemotoXYZ",
  filename: "remotoxyz",
  companyName: "Empresa XYZ Ltda",

  // Configurações de Display (NOVO!)
  customImageQuality: 80,
  codecPreference: "vp9",
  enableHwCodec: true,
  fps: 30,
  displayMode: "adaptive",

  // Segurança
  connectionDirection: "Incoming",
  disableSettings: true,
  permanentPassword: "senha_fixa_123",

  // Permissões
  enableKeyboard: true,
  enableClipboard: true,
  enableFileTransfer: true
};

// Iniciar build
const response = await axios.post('https://rdgen.nextcoreti.com.br/api/build', config, {
  headers: {
    'Content-Type': 'application/json',
    // Opcional: usar API key para multi-tenant
    // 'X-API-Key': 'sua_api_key_aqui'
  }
});

const jobId = response.data.data.id;
console.log(`Build iniciado: ${jobId}`);

// Acompanhar progresso
const checkStatus = async () => {
  const status = await axios.get(`https://rdgen.nextcoreti.com.br/api/status/${jobId}`);
  const job = status.data.data;

  console.log(`Status: ${job.status} (${job.progress}%)`);
  console.log(`Mensagem: ${job.statusMessage}`);

  if (job.status === 'completed') {
    console.log(`Download EXE: ${job.artifactUrl}`);
    console.log(`Download MSI: ${job.artifactMsiUrl}`);
    return true;
  }

  if (job.status === 'failed') {
    console.error('Build falhou!');
    return true;
  }

  return false;
};

// Polling a cada 10 segundos
const interval = setInterval(async () => {
  const done = await checkStatus();
  if (done) clearInterval(interval);
}, 10000);
```

---

## 🔗 Exemplo 2: Gerar Token de Conexão Temporário

```javascript
// Seu sistema RMM chama esta API para gerar token
const tokenResponse = await axios.post('https://rdgen.nextcoreti.com.br/api/token/generate', {
  deviceId: "123456789",  // ID do RustDesk do cliente
  password: "abc123"       // Senha temporária do dispositivo
});

const { token, rustdeskUrl, expiresIn } = tokenResponse.data;

console.log(`Token válido por ${expiresIn} segundos`);
console.log(`URL RustDesk: ${rustdeskUrl}`);

// Enviar para o agente do técnico via WebSocket
websocket.send({
  action: 'connect',
  rustdeskUrl: rustdeskUrl
});

// O agente executa: start rustdesk://connection/new/123456789?token=...
```

---

## 🖼️ Exemplo 3: Upload de Ícone/Logo

```javascript
const FormData = require('form-data');
const fs = require('fs');

const form = new FormData();
form.append('file', fs.createReadStream('/caminho/para/icon.png'));

const uploadResponse = await axios.post('https://rdgen.nextcoreti.com.br/api/upload/icon', form, {
  headers: form.getHeaders()
});

const iconBase64 = uploadResponse.data.data.base64;

// Usar no BuildConfig
const config = {
  ...outrasConfigs,
  iconBase64: iconBase64,
  logoBase64: logoBase64
};
```

---

## 🔑 Exemplo 4: Usar API Key (Multi-Tenant)

```javascript
// Todas as requisições com API key
const headers = {
  'X-API-Key': 'sua_chave_api_aqui_64_caracteres',
  'Content-Type': 'application/json'
};

// Iniciar build
await axios.post('https://rdgen.nextcoreti.com.br/api/build', config, { headers });

// Ver minhas informações
const me = await axios.get('https://rdgen.nextcoreti.com.br/api/me', { headers });
console.log(`Tenant: ${me.data.data.tenantId}`);
console.log(`Builds hoje: ${me.data.data.buildsToday}`);
console.log(`Limite: ${me.data.data.rateLimit}`);

// Listar meus builds
const myBuilds = await axios.get('https://rdgen.nextcoreti.com.br/api/me/builds', { headers });
console.log(`Total de builds: ${myBuilds.data.data.length}`);
```

---

## 🐍 Exemplo 5: Python

```python
import requests
import time

# Iniciar build
config = {
    "configName": "Cliente Python",
    "platform": "windows",
    "version": "1.4.5",
    "host": "rustdesk.example.com",
    "key": "sua_chave_aqui",
    "apiServer": "https://api.example.com",
    "customImageQuality": 80,
    "codecPreference": "vp9",
    "fps": 30
}

response = requests.post(
    'https://rdgen.nextcoreti.com.br/api/build',
    json=config,
    headers={'Content-Type': 'application/json'}
)

job_id = response.json()['data']['id']
print(f"Build iniciado: {job_id}")

# Acompanhar progresso
while True:
    status_response = requests.get(f'https://rdgen.nextcoreti.com.br/api/status/{job_id}')
    job = status_response.json()['data']

    print(f"Status: {job['status']} ({job['progress']}%)")

    if job['status'] in ['completed', 'failed', 'cancelled']:
        break

    time.sleep(10)

if job['status'] == 'completed':
    print(f"Download: {job['artifactUrl']}")

    # Baixar artefato
    artifact_response = requests.get(f"https://rdgen.nextcoreti.com.br{job['artifactUrl']}")
    with open('rustdesk-custom.exe', 'wb') as f:
        f.write(artifact_response.content)
    print("Download concluído!")
```

---

## 🔧 Exemplo 6: PHP

```php
<?php

// Iniciar build
$config = [
    'configName' => 'Cliente PHP',
    'platform' => 'windows',
    'version' => '1.4.5',
    'host' => 'rustdesk.example.com',
    'key' => 'sua_chave_aqui',
    'apiServer' => 'https://api.example.com',
    'customImageQuality' => 80,
    'codecPreference' => 'vp9',
    'fps' => 30
];

$ch = curl_init('https://rdgen.nextcoreti.com.br/api/build');
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($config));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = json_decode(curl_exec($ch), true);
curl_close($ch);

$jobId = $response['data']['id'];
echo "Build iniciado: $jobId\n";

// Acompanhar progresso
do {
    sleep(10);

    $ch = curl_init("https://rdgen.nextcoreti.com.br/api/status/$jobId");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $statusResponse = json_decode(curl_exec($ch), true);
    curl_close($ch);

    $job = $statusResponse['data'];
    echo "Status: {$job['status']} ({$job['progress']}%)\n";

} while (!in_array($job['status'], ['completed', 'failed', 'cancelled']));

if ($job['status'] === 'completed') {
    echo "Download: {$job['artifactUrl']}\n";
}
?>
```

---

## 📊 Tipos de Plataforma

```javascript
const platforms = [
  "windows",      // Windows 64-bit (EXE + MSI)
  "windows-x86",  // Windows 32-bit (EXE)
  "linux",        // Linux (DEB, RPM, AppImage, PKG)
  "android",      // Android (APK)
  "macos"         // macOS (DMG x64 + ARM64)
];
```

---

## 🎨 Configurações de Display (Novo!)

```javascript
{
  // Qualidade de imagem (0-100)
  customImageQuality: 80,

  // Codec de vídeo
  codecPreference: "vp9",  // vp9, vp8, h264, h265, av1

  // Usar GPU para encoding
  enableHwCodec: true,

  // Frames por segundo
  fps: 30,  // 15, 30, 60

  // Modo de exibição
  displayMode: "adaptive"  // adaptive, original, fit
}
```

---

## 🔐 Status do Build

- **pending**: Build criado, aguardando processamento
- **queued**: Na fila do GitHub Actions
- **in_progress**: Build em andamento (0-100%)
- **completed**: Build finalizado com sucesso
- **failed**: Build falhou (ver logs)
- **cancelled**: Build cancelado pelo usuário

---

## 📞 Suporte

- **Documentação**: https://rdgen.nextcoreti.com.br/api-docs
- **Health Check**: https://rdgen.nextcoreti.com.br/api/health

---

## ⚡ Dicas

1. **Polling**: Consulte status a cada 10-15 segundos
2. **Timeout**: Builds podem levar 5-15 minutos
3. **Rate Limit**: Use API key para evitar limitações
4. **Webhooks**: Em breve! (notificação quando build completar)
5. **Display**: Configure codec VP9 + HW aceleração para melhor performance
6. **FPS**: Use 60 FPS apenas para trabalhos gráficos/animações
