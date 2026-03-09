'use client';

import { useState } from 'react';

interface ApiResponse {
  success: boolean;
  data?: any;
  error?: string;
}

const DEFAULT_BUILD_CONFIG = {
  platform: 'windows',
  version: '1.4.4',
  configName: 'MeuCliente',
  appName: 'Suporte Remoto',
  filename: 'suporte-remoto',
  connectionDirection: 'Both',
  disableInstallation: false,
  disableSettings: false,
  host: '',
  key: '',
  apiServer: '',
  urlLink: '',
  downloadLink: '',
  companyName: '',
  approveMode: 'password-click',
  permanentPassword: '',
  denyLanDiscovery: false,
  enableDirectIp: false,
  autoCloseInactivity: false,
  allowHideConnectionWindow: false,
  theme: 'system',
  themeMode: 'default',
  permissionsMode: 'default',
  permissionsType: 'full',
  enableKeyboard: true,
  enableClipboard: true,
  enableFileTransfer: true,
  enableAudio: true,
  enableTcp: true,
  enableRemoteRestart: true,
  enableRecording: true,
  enableBlockingInput: true,
  enableRemoteConfig: true,
  enablePrinter: true,
  enableCamera: true,
  enableTerminal: true,
  cycleMonitor: false,
  xOffline: false,
  removeNewVersionNotif: false,
  delayFix: false,
  removeWallpaper: false,
  defaultSettings: '',
  overrideSettings: '',
};

export default function ApiDocsPage() {
  const [baseUrl, setBaseUrl] = useState('');
  const [adminSecret, setAdminSecret] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [response, setResponse] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'admin' | 'client' | 'examples'>('client');

  // Form states for creating API key
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyTenantId, setNewKeyTenantId] = useState('');
  const [newKeyRateLimit, setNewKeyRateLimit] = useState('10');
  const [newKeyExpires, setNewKeyExpires] = useState('');

  // Build config state
  const [buildConfig, setBuildConfig] = useState({ ...DEFAULT_BUILD_CONFIG });

  // Get base URL - use proxy by default, or custom URL if specified
  const getBaseUrl = () => {
    if (baseUrl) return baseUrl;
    // Use same origin - Next.js rewrites will proxy to backend
    return '';
  };

  // Get external URL for examples (showing actual backend URL)
  const getExternalUrl = () => {
    if (baseUrl) return baseUrl;
    if (typeof window !== 'undefined') {
      return `${window.location.protocol}//${window.location.hostname}:4000`;
    }
    return 'http://localhost:4000';
  };

  // Execute API request
  const executeRequest = async (
    method: string,
    endpoint: string,
    body?: any,
    useAdminSecret = false,
    useApiKey = false
  ) => {
    setLoading(true);
    setResponse(null);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      if (useAdminSecret && adminSecret) {
        headers['X-Admin-Secret'] = adminSecret;
      }

      if (useApiKey && apiKey) {
        headers['X-API-Key'] = apiKey;
      }

      const res = await fetch(`${getBaseUrl()}${endpoint}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });

      const data = await res.json();
      setResponse(data);
    } catch (error: any) {
      setResponse({
        success: false,
        error: error.message || 'Request failed',
      });
    } finally {
      setLoading(false);
    }
  };

  const updateBuildConfig = (key: string, value: any) => {
    setBuildConfig(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-4 md:p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-3xl font-bold">RDGen API</h1>
            <p className="text-gray-400">Documentacao e testes da API para integracao multitenant</p>
          </div>
          <a href="/" className="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded text-sm">
            Voltar ao Gerador
          </a>
        </div>

        {/* Configuration */}
        <div className="bg-gray-800 rounded-lg p-4 mb-6">
          <h2 className="text-lg font-semibold mb-3">Configuracao de Autenticacao</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm text-gray-400 mb-1">Base URL da API</label>
              <input
                type="text"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder={getBaseUrl()}
                className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">Admin Secret</label>
              <input
                type="password"
                value={adminSecret}
                onChange={(e) => setAdminSecret(e.target.value)}
                placeholder="Para gerenciar API Keys"
                className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-400 mb-1">API Key do Cliente</label>
              <input
                type="text"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="rdgen_..."
                className="w-full bg-gray-700 rounded px-3 py-2 text-sm font-mono text-xs"
              />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-6 flex-wrap">
          <button
            onClick={() => setActiveTab('client')}
            className={`px-4 py-2 rounded-lg font-medium ${
              activeTab === 'client'
                ? 'bg-green-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            Testar Build (Cliente)
          </button>
          <button
            onClick={() => setActiveTab('admin')}
            className={`px-4 py-2 rounded-lg font-medium ${
              activeTab === 'admin'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            Gerenciar API Keys (Admin)
          </button>
          <button
            onClick={() => setActiveTab('examples')}
            className={`px-4 py-2 rounded-lg font-medium ${
              activeTab === 'examples'
                ? 'bg-purple-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            Exemplos de Codigo
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left side - Forms */}
          <div className="lg:col-span-2 space-y-6">

            {/* CLIENT TAB - Build Form */}
            {activeTab === 'client' && (
              <>
                {/* Quick Actions */}
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="font-semibold mb-3">Acoes Rapidas</h3>
                  <div className="flex gap-2 flex-wrap">
                    <button
                      onClick={() => executeRequest('GET', '/api/health')}
                      disabled={loading}
                      className="bg-gray-600 hover:bg-gray-500 px-3 py-2 rounded text-sm"
                    >
                      Health Check
                    </button>
                    <button
                      onClick={() => executeRequest('GET', '/api/me', undefined, false, true)}
                      disabled={loading || !apiKey}
                      className="bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded text-sm disabled:opacity-50"
                    >
                      Meus Dados
                    </button>
                    <button
                      onClick={() => executeRequest('GET', '/api/me/builds', undefined, false, true)}
                      disabled={loading || !apiKey}
                      className="bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded text-sm disabled:opacity-50"
                    >
                      Meus Builds
                    </button>
                  </div>
                </div>

                {/* Build Form */}
                <div className="bg-gray-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="bg-yellow-600 text-xs px-2 py-1 rounded">POST</span>
                    <code className="text-sm">/api/build</code>
                    <span className="text-gray-400 text-sm ml-2">- Criar nova build</span>
                  </div>

                  {/* Basic Info */}
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-gray-300 mb-2">Informacoes Basicas</h4>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Nome Config *</label>
                        <input
                          type="text"
                          value={buildConfig.configName}
                          onChange={(e) => updateBuildConfig('configName', e.target.value)}
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Nome do App</label>
                        <input
                          type="text"
                          value={buildConfig.appName}
                          onChange={(e) => updateBuildConfig('appName', e.target.value)}
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Nome Arquivo</label>
                        <input
                          type="text"
                          value={buildConfig.filename}
                          onChange={(e) => updateBuildConfig('filename', e.target.value)}
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Plataforma</label>
                        <select
                          value={buildConfig.platform}
                          onChange={(e) => updateBuildConfig('platform', e.target.value)}
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        >
                          <option value="windows">Windows 64-bit</option>
                          <option value="windows-x86">Windows 32-bit</option>
                          <option value="linux">Linux</option>
                          <option value="android">Android</option>
                          <option value="macos">macOS</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Versao</label>
                        <select
                          value={buildConfig.version}
                          onChange={(e) => updateBuildConfig('version', e.target.value)}
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        >
                          <option value="nightly">Nightly</option>
                          <option value="1.4.4">1.4.4</option>
                          <option value="1.4.3">1.4.3</option>
                          <option value="1.4.2">1.4.2</option>
                          <option value="1.4.1">1.4.1</option>
                          <option value="1.4.0">1.4.0</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Direcao Conexao</label>
                        <select
                          value={buildConfig.connectionDirection}
                          onChange={(e) => updateBuildConfig('connectionDirection', e.target.value)}
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        >
                          <option value="Both">Ambos</option>
                          <option value="Incoming">Apenas Receber</option>
                          <option value="Outgoing">Apenas Conectar</option>
                        </select>
                      </div>
                    </div>
                  </div>

                  {/* Server Config */}
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-gray-300 mb-2">Configuracao do Servidor</h4>
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Host (Rendezvous)</label>
                        <input
                          type="text"
                          value={buildConfig.host}
                          onChange={(e) => updateBuildConfig('host', e.target.value)}
                          placeholder="rs.seudominio.com"
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Key Publica</label>
                        <input
                          type="text"
                          value={buildConfig.key}
                          onChange={(e) => updateBuildConfig('key', e.target.value)}
                          placeholder="Chave publica do servidor"
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">API Server</label>
                        <input
                          type="text"
                          value={buildConfig.apiServer}
                          onChange={(e) => updateBuildConfig('apiServer', e.target.value)}
                          placeholder="https://api.seudominio.com"
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Nome Empresa</label>
                        <input
                          type="text"
                          value={buildConfig.companyName}
                          onChange={(e) => updateBuildConfig('companyName', e.target.value)}
                          placeholder="Minha Empresa"
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Security */}
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-gray-300 mb-2">Seguranca</h4>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Modo Aprovacao</label>
                        <select
                          value={buildConfig.approveMode}
                          onChange={(e) => updateBuildConfig('approveMode', e.target.value)}
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        >
                          <option value="password">Senha</option>
                          <option value="click">Clique</option>
                          <option value="password-click">Senha + Clique</option>
                        </select>
                      </div>
                      <div>
                        <label className="block text-xs text-gray-400 mb-1">Senha Permanente</label>
                        <input
                          type="text"
                          value={buildConfig.permanentPassword}
                          onChange={(e) => updateBuildConfig('permanentPassword', e.target.value)}
                          placeholder="Opcional"
                          className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Options */}
                  <div className="mb-4">
                    <h4 className="text-sm font-medium text-gray-300 mb-2">Opcoes</h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                      {[
                        { key: 'disableInstallation', label: 'Desabilitar Instalacao' },
                        { key: 'disableSettings', label: 'Desabilitar Config' },
                        { key: 'denyLanDiscovery', label: 'Bloquear LAN Discovery' },
                        { key: 'enableDirectIp', label: 'Permitir IP Direto' },
                        { key: 'removeNewVersionNotif', label: 'Remover Notif. Versao' },
                        { key: 'removeWallpaper', label: 'Remover Wallpaper' },
                        { key: 'cycleMonitor', label: 'Cycle Monitor' },
                        { key: 'delayFix', label: 'Delay Fix' },
                      ].map(({ key, label }) => (
                        <label key={key} className="flex items-center gap-2 text-sm cursor-pointer">
                          <input
                            type="checkbox"
                            checked={buildConfig[key as keyof typeof buildConfig] as boolean}
                            onChange={(e) => updateBuildConfig(key, e.target.checked)}
                            className="rounded"
                          />
                          {label}
                        </label>
                      ))}
                    </div>
                  </div>

                  {/* Submit */}
                  <div className="flex gap-2">
                    <button
                      onClick={() => {
                        const config: any = { ...buildConfig };
                        // Remove campos vazios
                        Object.keys(config).forEach(key => {
                          if (config[key] === '' || config[key] === undefined) delete config[key];
                        });
                        executeRequest('POST', '/api/build', config, false, !!apiKey);
                      }}
                      disabled={loading || !buildConfig.configName}
                      className="bg-green-600 hover:bg-green-700 px-6 py-2 rounded font-medium disabled:opacity-50"
                    >
                      {loading ? 'Enviando...' : 'Iniciar Build'}
                    </button>
                    <button
                      onClick={() => setBuildConfig({ ...DEFAULT_BUILD_CONFIG })}
                      className="bg-gray-600 hover:bg-gray-500 px-4 py-2 rounded text-sm"
                    >
                      Reset
                    </button>
                  </div>

                  {!apiKey && (
                    <p className="text-yellow-500 text-xs mt-2">
                      Sem API Key: build funcionara mas sem rate limit ou tracking
                    </p>
                  )}
                </div>

                {/* Check Build Status */}
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="font-semibold mb-3">Verificar Status de Build</h3>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      id="jobIdInput"
                      placeholder="Job ID (do resultado acima)"
                      className="flex-1 bg-gray-700 rounded px-3 py-2 text-sm"
                    />
                    <button
                      onClick={() => {
                        const jobId = (document.getElementById('jobIdInput') as HTMLInputElement)?.value;
                        if (jobId) executeRequest('GET', `/api/status/${jobId}`);
                      }}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded text-sm"
                    >
                      Verificar
                    </button>
                  </div>
                </div>
              </>
            )}

            {/* ADMIN TAB */}
            {activeTab === 'admin' && (
              <>
                {/* Create API Key */}
                <div className="bg-gray-800 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-4">
                    <span className="bg-yellow-600 text-xs px-2 py-1 rounded">POST</span>
                    <code className="text-sm">/api/admin/apikeys</code>
                    <span className="text-gray-400 text-sm ml-2">- Criar API Key</span>
                  </div>

                  <div className="grid grid-cols-2 gap-3 mb-4">
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Nome do Cliente *</label>
                      <input
                        type="text"
                        value={newKeyName}
                        onChange={(e) => setNewKeyName(e.target.value)}
                        placeholder="Ex: Empresa ABC"
                        className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Tenant ID (unico) *</label>
                      <input
                        type="text"
                        value={newKeyTenantId}
                        onChange={(e) => setNewKeyTenantId(e.target.value)}
                        placeholder="Ex: empresa-abc"
                        className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Rate Limit (builds/dia)</label>
                      <input
                        type="number"
                        value={newKeyRateLimit}
                        onChange={(e) => setNewKeyRateLimit(e.target.value)}
                        className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-gray-400 mb-1">Data Expiracao</label>
                      <input
                        type="date"
                        value={newKeyExpires}
                        onChange={(e) => setNewKeyExpires(e.target.value)}
                        className="w-full bg-gray-700 rounded px-3 py-2 text-sm"
                      />
                    </div>
                  </div>

                  <button
                    onClick={() =>
                      executeRequest(
                        'POST',
                        '/api/admin/apikeys',
                        {
                          name: newKeyName,
                          tenantId: newKeyTenantId,
                          rateLimit: parseInt(newKeyRateLimit) || 10,
                          expiresAt: newKeyExpires || undefined,
                        },
                        true
                      )
                    }
                    disabled={loading || !adminSecret || !newKeyName || !newKeyTenantId}
                    className="bg-green-600 hover:bg-green-700 px-6 py-2 rounded font-medium disabled:opacity-50"
                  >
                    Criar API Key
                  </button>

                  {!adminSecret && (
                    <p className="text-red-400 text-xs mt-2">
                      Preencha o Admin Secret acima para usar este endpoint
                    </p>
                  )}
                </div>

                {/* List API Keys */}
                <div className="bg-gray-800 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-2">
                      <span className="bg-green-600 text-xs px-2 py-1 rounded">GET</span>
                      <code className="text-sm">/api/admin/apikeys</code>
                    </div>
                    <button
                      onClick={() => executeRequest('GET', '/api/admin/apikeys', undefined, true)}
                      disabled={loading || !adminSecret}
                      className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded text-sm disabled:opacity-50"
                    >
                      Listar Todas
                    </button>
                  </div>
                </div>

                {/* List Jobs */}
                <div className="bg-gray-800 rounded-lg p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="bg-green-600 text-xs px-2 py-1 rounded">GET</span>
                      <code className="text-sm">/api/jobs</code>
                      <span className="text-gray-400 text-sm ml-2">- Todos os jobs</span>
                    </div>
                    <button
                      onClick={() => executeRequest('GET', '/api/jobs')}
                      disabled={loading}
                      className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded text-sm"
                    >
                      Listar Jobs
                    </button>
                  </div>
                </div>
              </>
            )}

            {/* EXAMPLES TAB */}
            {activeTab === 'examples' && (
              <>
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="font-semibold mb-4">cURL - Criar API Key (Admin)</h3>
                  <pre className="bg-gray-900 rounded p-4 overflow-auto text-xs whitespace-pre-wrap">
{`curl -X POST ${getBaseUrl()}/api/admin/apikeys \\
  -H "Content-Type: application/json" \\
  -H "X-Admin-Secret: SEU_ADMIN_SECRET" \\
  -d '{
    "name": "Cliente XYZ",
    "tenantId": "cliente-xyz",
    "rateLimit": 10,
    "expiresAt": "2025-12-31"
  }'`}
                  </pre>
                </div>

                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="font-semibold mb-4">cURL - Criar Build (Cliente)</h3>
                  <pre className="bg-gray-900 rounded p-4 overflow-auto text-xs whitespace-pre-wrap">
{`curl -X POST ${getBaseUrl()}/api/build \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: rdgen_SUA_API_KEY" \\
  -d '{
    "configName": "MeuCliente",
    "appName": "Suporte Remoto",
    "filename": "suporte-remoto",
    "platform": "windows",
    "version": "1.4.4",
    "host": "rs.seudominio.com",
    "key": "SUA_CHAVE_PUBLICA"
  }'`}
                  </pre>
                </div>

                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="font-semibold mb-4">JavaScript/TypeScript</h3>
                  <pre className="bg-gray-900 rounded p-4 overflow-auto text-xs whitespace-pre-wrap">
{`// Criar build
const response = await fetch('${getBaseUrl()}/api/build', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': 'rdgen_SUA_API_KEY'
  },
  body: JSON.stringify({
    configName: 'MeuCliente',
    appName: 'Suporte Remoto',
    platform: 'windows',
    version: '1.4.4',
    host: 'rs.seudominio.com',
    key: 'SUA_CHAVE_PUBLICA'
  })
});

const { success, data } = await response.json();
const jobId = data.id;

// Verificar status
const statusRes = await fetch(\`${getBaseUrl()}/api/status/\${jobId}\`);
const status = await statusRes.json();
console.log('Status:', status.data.status);

// Quando completar, baixar artifact
if (status.data.status === 'completed') {
  window.open(\`${getBaseUrl()}/api/artifact/\${jobId}?type=exe\`);
}`}
                  </pre>
                </div>

                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="font-semibold mb-4">PHP</h3>
                  <pre className="bg-gray-900 rounded p-4 overflow-auto text-xs whitespace-pre-wrap">
{`<?php
// Criar build
$ch = curl_init('${getBaseUrl()}/api/build');
curl_setopt_array($ch, [
  CURLOPT_POST => true,
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_HTTPHEADER => [
    'Content-Type: application/json',
    'X-API-Key: rdgen_SUA_API_KEY'
  ],
  CURLOPT_POSTFIELDS => json_encode([
    'configName' => 'MeuCliente',
    'appName' => 'Suporte Remoto',
    'platform' => 'windows',
    'version' => '1.4.4',
    'host' => 'rs.seudominio.com',
    'key' => 'SUA_CHAVE_PUBLICA'
  ])
]);

$response = json_decode(curl_exec($ch), true);
$jobId = $response['data']['id'];

// Verificar status (polling)
do {
  sleep(10);
  $status = json_decode(file_get_contents(
    "${getBaseUrl()}/api/status/" . $jobId
  ), true);
} while ($status['data']['status'] === 'in_progress');

// Download
if ($status['data']['status'] === 'completed') {
  $downloadUrl = "${getBaseUrl()}/api/artifact/" . $jobId . "?type=exe";
  echo "Download: " . $downloadUrl;
}
?>`}
                  </pre>
                </div>

                {/* API Reference Table */}
                <div className="bg-gray-800 rounded-lg p-4">
                  <h3 className="font-semibold mb-4">Referencia Completa da API</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="bg-gray-700">
                        <tr>
                          <th className="px-3 py-2 text-left">Metodo</th>
                          <th className="px-3 py-2 text-left">Endpoint</th>
                          <th className="px-3 py-2 text-left">Auth</th>
                          <th className="px-3 py-2 text-left">Descricao</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-700">
                        <tr><td className="px-3 py-2"><span className="bg-green-600 text-xs px-1 rounded">GET</span></td><td className="px-3 py-2 font-mono text-xs">/api/health</td><td className="px-3 py-2 text-gray-400">-</td><td className="px-3 py-2">Status da API</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-yellow-600 text-xs px-1 rounded">POST</span></td><td className="px-3 py-2 font-mono text-xs">/api/build</td><td className="px-3 py-2 text-green-400">API Key*</td><td className="px-3 py-2">Criar build</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-green-600 text-xs px-1 rounded">GET</span></td><td className="px-3 py-2 font-mono text-xs">/api/status/:jobId</td><td className="px-3 py-2 text-gray-400">-</td><td className="px-3 py-2">Status do job</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-green-600 text-xs px-1 rounded">GET</span></td><td className="px-3 py-2 font-mono text-xs">/api/artifact/:jobId</td><td className="px-3 py-2 text-gray-400">-</td><td className="px-3 py-2">Download artifact</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-green-600 text-xs px-1 rounded">GET</span></td><td className="px-3 py-2 font-mono text-xs">/api/me</td><td className="px-3 py-2 text-green-400">API Key</td><td className="px-3 py-2">Info do tenant</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-green-600 text-xs px-1 rounded">GET</span></td><td className="px-3 py-2 font-mono text-xs">/api/me/builds</td><td className="px-3 py-2 text-green-400">API Key</td><td className="px-3 py-2">Builds do tenant</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-yellow-600 text-xs px-1 rounded">POST</span></td><td className="px-3 py-2 font-mono text-xs">/api/admin/apikeys</td><td className="px-3 py-2 text-blue-400">Admin</td><td className="px-3 py-2">Criar API Key</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-green-600 text-xs px-1 rounded">GET</span></td><td className="px-3 py-2 font-mono text-xs">/api/admin/apikeys</td><td className="px-3 py-2 text-blue-400">Admin</td><td className="px-3 py-2">Listar API Keys</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-blue-600 text-xs px-1 rounded">PUT</span></td><td className="px-3 py-2 font-mono text-xs">/api/admin/apikeys/:id</td><td className="px-3 py-2 text-blue-400">Admin</td><td className="px-3 py-2">Atualizar API Key</td></tr>
                        <tr><td className="px-3 py-2"><span className="bg-red-600 text-xs px-1 rounded">DEL</span></td><td className="px-3 py-2 font-mono text-xs">/api/admin/apikeys/:id</td><td className="px-3 py-2 text-blue-400">Admin</td><td className="px-3 py-2">Excluir API Key</td></tr>
                      </tbody>
                    </table>
                  </div>
                  <p className="text-gray-400 text-xs mt-3">
                    * API Key opcional para /api/build - sem API Key funciona mas sem rate limit/tracking<br/>
                    Admin = Header X-Admin-Secret | API Key = Header X-API-Key
                  </p>
                </div>
              </>
            )}
          </div>

          {/* Right side - Response */}
          <div className="lg:col-span-1">
            <div className="bg-gray-800 rounded-lg p-4 sticky top-4">
              <h3 className="text-lg font-semibold mb-4">Resposta da API</h3>
              {loading && (
                <div className="flex items-center gap-2 text-gray-400">
                  <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Carregando...
                </div>
              )}
              {response && (
                <div>
                  <div className={`inline-block px-2 py-1 rounded text-xs mb-2 ${
                    response.success ? 'bg-green-600' : 'bg-red-600'
                  }`}>
                    {response.success ? 'SUCCESS' : 'ERROR'}
                  </div>
                  <pre className="bg-gray-900 rounded p-3 overflow-auto max-h-[70vh] text-xs">
                    {JSON.stringify(response, null, 2)}
                  </pre>

                  {/* Quick actions based on response */}
                  {response.success && response.data?.id && (
                    <div className="mt-3 space-y-2">
                      {response.data.key && (
                        <div className="bg-green-900/30 border border-green-600 rounded p-2">
                          <p className="text-xs text-green-400 mb-1">API Key criada! Copie:</p>
                          <code className="text-xs break-all">{response.data.key}</code>
                        </div>
                      )}
                      {response.data.status && (
                        <button
                          onClick={() => executeRequest('GET', `/api/status/${response.data.id}`)}
                          className="w-full bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded text-sm"
                        >
                          Atualizar Status
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}
              {!loading && !response && (
                <div className="text-gray-500 text-center py-8">
                  <p>Execute uma requisicao</p>
                  <p className="text-sm mt-1">para ver o resultado aqui</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
