'use client';

import { useState, useEffect, useRef } from 'react';
import { BuildConfig, ClientListItem, ClientProfile } from '@/types';
import { listClients, getClient, getClientVersion } from '@/lib/api';
import toast from 'react-hot-toast';

interface ClientSelectorProps {
  currentConfig: BuildConfig;
  onConfigLoad: (config: BuildConfig) => void;
  selectedClientId: string | null;
  onSelectClient: (clientId: string | null) => void;
  onClientListChange?: (clients: {id: string; name: string}[]) => void;
}

export default function ClientSelector({
  currentConfig,
  onConfigLoad,
  selectedClientId,
  onSelectClient,
  onClientListChange,
}: ClientSelectorProps) {
  const [clients, setClients] = useState<ClientListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingVersion, setLoadingVersion] = useState(false);
  const [selectedClient, setSelectedClient] = useState<ClientProfile | null>(null);
  const [selectedVersionId, setSelectedVersionId] = useState<string>('');
  const [showPassword, setShowPassword] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => { loadClients(); }, []);

  useEffect(() => {
    if (selectedClientId) {
      loadClients().then(() => {
        getClient(selectedClientId).then((result) => {
          if (result.success && result.data) {
            setSelectedClient(result.data);
            setSelectedVersionId(result.data.latestVersionId);
            setSearchTerm(result.data.name);
          }
        });
      });
    } else {
      setSelectedClient(null);
      setSelectedVersionId('');
      setSearchTerm('');
    }
  }, [selectedClientId]);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
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
    c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.host.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleSelectClient = async (clientId: string) => {
    setShowDropdown(false);
    setShowPassword(false);

    if (clientId === 'new') {
      onSelectClient(null);
      setSelectedClient(null);
      setSelectedVersionId('');
      setSearchTerm('');
      return;
    }

    onSelectClient(clientId);
    const client = clients.find(c => c.id === clientId);
    if (client) setSearchTerm(client.name);

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
      toast.success('Configuracao carregada');
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

      <div className="flex gap-3 items-end">
        <div className="flex-1 relative" ref={dropdownRef}>
          <label className="input-label">Perfil do cliente</label>
          <div className="relative">
            <input
              ref={inputRef}
              type="text"
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setShowDropdown(true);
                if (!e.target.value) {
                  onSelectClient(null);
                  setSelectedClient(null);
                  setSelectedVersionId('');
                }
              }}
              onFocus={() => setShowDropdown(true)}
              placeholder={loading ? 'Carregando...' : 'Buscar cliente...'}
              className="input-field pr-8"
              disabled={loading}
            />
            {selectedClientId && (
              <button
                type="button"
                onClick={() => {
                  onSelectClient(null);
                  setSelectedClient(null);
                  setSelectedVersionId('');
                  setSearchTerm('');
                  inputRef.current?.focus();
                }}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
              >
                <i className="fas fa-times text-xs"></i>
              </button>
            )}
          </div>

          {showDropdown && !selectedClientId && (
            <div className="absolute z-50 w-full mt-1 bg-[#1a1a1a] border border-[#444] rounded-lg shadow-xl max-h-60 overflow-y-auto">
              <button
                type="button"
                onClick={() => handleSelectClient('new')}
                className="w-full text-left px-3 py-2 hover:bg-[#333] text-white text-sm border-b border-[#333] flex items-center gap-2"
              >
                <i className="fas fa-plus text-green-400 text-xs"></i>
                Novo Cliente
              </button>
              {filteredClients.length === 0 ? (
                <div className="px-3 py-2 text-gray-500 text-sm">
                  {searchTerm ? 'Nenhum cliente encontrado' : 'Nenhum cliente cadastrado'}
                </div>
              ) : (
                filteredClients.map((client) => (
                  <button
                    key={client.id}
                    type="button"
                    onClick={() => handleSelectClient(client.id)}
                    className="w-full text-left px-3 py-2 hover:bg-[#333] text-white text-sm flex items-center justify-between"
                  >
                    <div>
                      <span className="font-medium">{client.name}</span>
                      <span className="text-gray-500 text-xs ml-2">{client.host}</span>
                    </div>
                    <span className="text-gray-500 text-xs">
                      {client.versionCount}v
                    </span>
                  </button>
                ))
              )}
            </div>
          )}
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
                    {idx === 0 ? '* ' : ''}v{selectedClient.versions.length - idx} -{' '}
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
