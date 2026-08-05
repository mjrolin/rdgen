'use client';

import { useState, useEffect } from 'react';
import { BuildConfig, ClientListItem, ClientProfile } from '@/types';
import { listClients, getClient, getClientVersion } from '@/lib/api';
import toast from 'react-hot-toast';

interface ClientSelectorProps {
  currentConfig: BuildConfig;
  onConfigLoad: (config: BuildConfig) => void;
  selectedClientId: string | null;
  onSelectClient: (clientId: string | null) => void;
}

export default function ClientSelector({
  currentConfig,
  onConfigLoad,
  selectedClientId,
  onSelectClient,
}: ClientSelectorProps) {
  const [clients, setClients] = useState<ClientListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingVersion, setLoadingVersion] = useState(false);
  const [selectedClient, setSelectedClient] = useState<ClientProfile | null>(null);
  const [selectedVersionId, setSelectedVersionId] = useState<string>('');
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    loadClients();
  }, []);

  const loadClients = async () => {
    setLoading(true);
    const result = await listClients();
    if (result.success && result.data) {
      setClients(result.data);
    }
    setLoading(false);
  };

  const handleClientChange = async (clientId: string) => {
    if (clientId === 'new') {
      onSelectClient(null);
      setSelectedClient(null);
      setSelectedVersionId('');
      return;
    }

    onSelectClient(clientId);
    setShowPassword(false);

    const result = await getClient(clientId);
    if (result.success && result.data) {
      setSelectedClient(result.data);
      setSelectedVersionId(result.data.latestVersionId);
      await loadVersion(clientId, result.data.latestVersionId);
    }
  };

  const loadVersion = async (clientId: string, versionId: string) => {
    setLoadingVersion(true);
    const result = await getClientVersion(clientId, versionId);
    if (result.success && result.data) {
      onConfigLoad(result.data as unknown as BuildConfig);
      toast.success('Configuracao carregada do perfil');
    } else {
      toast.error(result.error || 'Erro ao carregar versao');
    }
    setLoadingVersion(false);
  };

  const handleVersionChange = async (versionId: string) => {
    setSelectedVersionId(versionId);
    setShowPassword(false);
    if (selectedClientId) {
      await loadVersion(selectedClientId, versionId);
    }
  };

  return (
    <div className="section mb-4">
      <h2 className="section-title">
        <i className="fas fa-users text-sm"></i>
        Cliente
      </h2>

      <div className="flex gap-3 items-end">
        <div className="flex-1">
          <label className="input-label">Perfil do cliente</label>
          <select
            value={selectedClientId || 'new'}
            onChange={(e) => handleClientChange(e.target.value)}
            className="input-field"
            disabled={loading}
          >
            <option value="new">Novo Cliente</option>
            {clients.map((client) => (
              <option key={client.id} value={client.id}>
                {client.name} — {client.host} ({client.versionCount} versoes)
              </option>
            ))}
          </select>
        </div>

        {selectedClient && (
          <div className="flex-1">
            <label className="input-label">Versao de referencia</label>
            <select
              value={selectedVersionId}
              onChange={(e) => handleVersionChange(e.target.value)}
              className="input-field"
              disabled={loadingVersion}
            >
              {selectedClient.versions
                .slice()
                .reverse()
                .map((v, idx) => (
                  <option key={v.versionId} value={v.versionId}>
                    {idx === 0 ? '* ' : ''}v{selectedClient.versions.length - idx} —{' '}
                    {new Date(v.createdAt).toLocaleDateString('pt-BR')}
                    {v.label ? ` (${v.label})` : ''}
                  </option>
                ))}
            </select>
          </div>
        )}
      </div>

      {selectedClient && currentConfig.permanentPassword && (
        <div className="mt-2 flex items-center gap-2">
          <span className="text-gray-400 text-xs">Senha permanente:</span>
          <span className="text-white text-xs font-mono">
            {showPassword ? currentConfig.permanentPassword : '••••••••'}
          </span>
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="text-gray-400 hover:text-white text-xs"
          >
            <i className={`fas ${showPassword ? 'fa-eye-slash' : 'fa-eye'}`}></i>
          </button>
        </div>
      )}

      {loadingVersion && (
        <div className="mt-2 text-yellow-400 text-xs">
          <i className="fas fa-spinner fa-spin mr-1"></i>
          Carregando configuracao...
        </div>
      )}
    </div>
  );
}
