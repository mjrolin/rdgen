'use client';

import { useState, useEffect, useRef } from 'react';
import { BuildConfig, ClientListItem, ClientDetail, ProfileDetail } from '@/types';
import { listClients, getClient, getProfileVersion } from '@/lib/api';
import toast from 'react-hot-toast';

interface ClientSelectorProps {
  currentConfig: BuildConfig;
  onConfigLoad: (config: BuildConfig) => void;
  selectedClientId: string | null;
  selectedProfileId: string | null;
  onSelectClient: (clientId: string | null) => void;
  onSelectProfile: (profileId: string | null) => void;
  onClientListChange?: (clients: {id: string; name: string}[]) => void;
}

export default function ClientSelector({
  currentConfig,
  onConfigLoad,
  selectedClientId,
  selectedProfileId,
  onSelectClient,
  onSelectProfile,
  onClientListChange,
}: ClientSelectorProps) {
  const [clients, setClients] = useState<ClientListItem[]>([]);
  const [selectedClient, setSelectedClient] = useState<ClientDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingVersion, setLoadingVersion] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  // Search state for client
  const [clientSearch, setClientSearch] = useState('');
  const [showClientDropdown, setShowClientDropdown] = useState(false);
  const clientDropdownRef = useRef<HTMLDivElement>(null);
  const clientInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { loadClients(); }, []);

  useEffect(() => {
    if (selectedClientId) {
      loadClients().then(() => {
        getClient(selectedClientId).then((result) => {
          if (result.success && result.data) {
            setSelectedClient(result.data);
            setClientSearch(result.data.name);
          }
        });
      });
    } else {
      setSelectedClient(null);
      setClientSearch('');
    }
  }, [selectedClientId]);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (clientDropdownRef.current && !clientDropdownRef.current.contains(e.target as Node)) {
        setShowClientDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const loadClients = async () => {
    setLoading(true);
    const result = await listClients();
    if (result.success && result.data) {
      setClients(result.data);
      if (onClientListChange) {
        onClientListChange(result.data.map((c) => ({ id: c.id, name: c.name })));
      }
    }
    setLoading(false);
  };

  const filteredClients = clients.filter((c) =>
    c.name.toLowerCase().includes(clientSearch.toLowerCase())
  );

  const handleSelectClient = async (clientId: string) => {
    setShowClientDropdown(false);
    onSelectProfile(null);
    setShowPassword(false);

    if (clientId === 'new') {
      onSelectClient(null);
      setSelectedClient(null);
      setClientSearch('');
      return;
    }

    onSelectClient(clientId);
    const client = clients.find(c => c.id === clientId);
    if (client) setClientSearch(client.name);

    const result = await getClient(clientId);
    if (result.success && result.data) {
      setSelectedClient(result.data);
      // Auto-select latest profile
      if (result.data.profiles.length > 0) {
        const latest = result.data.profiles[result.data.profiles.length - 1];
        onSelectProfile(latest.profileId);
        await loadVersion(clientId, latest.profileId, latest.latestVersionId);
      }
    }
  };

  const handleSelectProfile = async (profileId: string) => {
    setShowPassword(false);
    onSelectProfile(profileId);

    if (!selectedClientId || !selectedClient) return;
    const profile = selectedClient.profiles.find(p => p.profileId === profileId);
    if (profile) {
      await loadVersion(selectedClientId, profileId, profile.latestVersionId);
    }
  };

  const loadVersion = async (clientId: string, profileId: string, versionId: string) => {
    setLoadingVersion(true);
    const result = await getProfileVersion(clientId, profileId, versionId);
    if (result.success && result.data) {
      onConfigLoad(result.data as unknown as BuildConfig);
      toast.success('Configuracao carregada');
    } else {
      toast.error(result.error || 'Erro ao carregar versao');
    }
    setLoadingVersion(false);
  };

  const handleVersionChange = async (versionId: string) => {
    setShowPassword(false);
    if (selectedClientId && selectedProfileId) {
      await loadVersion(selectedClientId, selectedProfileId, versionId);
    }
  };

  const selectedProfile = selectedClient?.profiles.find(p => p.profileId === selectedProfileId);

  return (
    <div className="section mb-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="section-title mb-0">
          <i className="fas fa-users text-sm"></i>
          Cliente
        </h2>
        <a href="/clientes" className="text-blue-400 hover:text-blue-300 text-xs">
          <i className="fas fa-cog mr-1"></i>
          Gerenciar
        </a>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Client selector */}
        <div className="relative" ref={clientDropdownRef}>
          <label className="input-label">Cliente</label>
          <div className="relative">
            <input
              ref={clientInputRef}
              type="text"
              value={clientSearch}
              onChange={(e) => {
                setClientSearch(e.target.value);
                setShowClientDropdown(true);
                if (!e.target.value) {
                  onSelectClient(null);
                  onSelectProfile(null);
                  setSelectedClient(null);
                }
              }}
              onFocus={() => setShowClientDropdown(true)}
              placeholder={loading ? 'Carregando...' : 'Buscar cliente...'}
              className="input-field pr-8"
              disabled={loading}
            />
            {selectedClientId && (
              <button
                type="button"
                onClick={() => {
                  onSelectClient(null);
                  onSelectProfile(null);
                  setSelectedClient(null);
                  setClientSearch('');
                  clientInputRef.current?.focus();
                }}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
              >
                <i className="fas fa-times text-xs"></i>
              </button>
            )}
          </div>

          {showClientDropdown && !selectedClientId && (
            <div className="absolute z-50 w-full mt-1 bg-[#1a1a1a] border border-[#444] rounded-lg shadow-xl max-h-48 overflow-y-auto">
              {filteredClients.length === 0 ? (
                <div className="px-3 py-2 text-gray-500 text-sm">
                  {clientSearch ? 'Nenhum cliente encontrado' : 'Nenhum cliente cadastrado'}
                </div>
              ) : (
                filteredClients.map((client) => (
                  <button
                    key={client.id}
                    type="button"
                    onClick={() => handleSelectClient(client.id)}
                    className="w-full text-left px-3 py-2 hover:bg-[#333] text-white text-sm flex items-center justify-between"
                  >
                    <span className="font-medium">{client.name}</span>
                    <span className="text-gray-500 text-xs">{client.profileCount} perfis</span>
                  </button>
                ))
              )}
            </div>
          )}
        </div>

        {/* Profile selector */}
        {selectedClient && selectedClient.profiles.length > 0 && (
          <div>
            <label className="input-label">Perfil</label>
            <select
              value={selectedProfileId || ''}
              onChange={(e) => handleSelectProfile(e.target.value)}
              className="input-field"
            >
              {selectedClient.profiles.map((profile) => (
                <option key={profile.profileId} value={profile.profileId}>
                  {profile.name} ({profile.platform}) — {profile.versions.length}v
                </option>
              ))}
            </select>
          </div>
        )}

        {/* Version selector */}
        {selectedProfile && selectedProfile.versions.length > 0 && (
          <div>
            <label className="input-label">Versao</label>
            <select
              value={selectedProfile.latestVersionId}
              onChange={(e) => handleVersionChange(e.target.value)}
              className="input-field"
              disabled={loadingVersion}
            >
              {selectedProfile.versions
                .slice()
                .reverse()
                .map((v, idx) => (
                  <option key={v.versionId} value={v.versionId}>
                    {idx === 0 ? '* ' : ''}v{selectedProfile.versions.length - idx} -{' '}
                    {new Date(v.createdAt).toLocaleDateString('pt-BR')}
                  </option>
                ))}
            </select>
          </div>
        )}
      </div>

      {selectedProfile && currentConfig.permanentPassword && (
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
