'use client';

import { useState, useEffect } from 'react';
import { ClientListItem, ClientDetail, ProfileListItem } from '@/types';
import { listClients, getClient, createClient, renameClient, deleteClient, createProfile, renameProfile, deleteProfile } from '@/lib/api';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';
import { LogoutButton } from '@/components/AuthGuard';
import { DEFAULT_BUILD_CONFIG } from '@/types';
import { canEdit, isAdmin } from '@/lib/permissions';

export default function ClientesPage() {
  const [clients, setClients] = useState<ClientListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedClientId, setExpandedClientId] = useState<string | null>(null);
  const [expandedClient, setExpandedClient] = useState<ClientDetail | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const [editProfileName, setEditProfileName] = useState('');
  const [showNewClientModal, setShowNewClientModal] = useState(false);
  const [showNewProfileModal, setShowNewProfileModal] = useState(false);
  const [newClientName, setNewClientName] = useState('');
  const [newProfileName, setNewProfileName] = useState('');
  const [newProfileHost, setNewProfileHost] = useState('');
  const [newProfilePlatform, setNewProfilePlatform] = useState('windows');
  const [creating, setCreating] = useState(false);
  const router = useRouter();

  useEffect(() => { loadClients(); }, []);

  const loadClients = async () => {
    setLoading(true);
    const result = await listClients();
    if (result.success && result.data) {
      setClients(result.data);
    }
    setLoading(false);
  };

  const filteredClients = clients.filter((c) =>
    c.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleExpandClient = async (clientId: string) => {
    if (expandedClientId === clientId) {
      setExpandedClientId(null);
      setExpandedClient(null);
      return;
    }
    setExpandedClientId(clientId);
    const result = await getClient(clientId);
    if (result.success && result.data) {
      setExpandedClient(result.data);
    }
  };

  const handleCreateClient = async () => {
    if (!newClientName.trim()) { toast.error('Nome obrigatorio'); return; }
    setCreating(true);
    const result = await createClient(newClientName.trim());
    if (result.success) {
      toast.success(`Cliente "${newClientName.trim()}" criado!`);
      setShowNewClientModal(false);
      setNewClientName('');
      await loadClients();
    } else {
      toast.error(result.error || 'Erro ao criar cliente');
    }
    setCreating(false);
  };

  const handleRenameClient = async (id: string) => {
    if (!editName.trim()) { toast.error('Nome obrigatorio'); return; }
    const result = await renameClient(id, editName.trim());
    if (result.success) {
      toast.success('Renomeado!');
      setEditingId(null);
      await loadClients();
      if (expandedClientId === id) handleExpandClient(id);
    } else {
      toast.error(result.error || 'Erro');
    }
  };

  const handleDeleteClient = async (id: string, name: string) => {
    if (!confirm(`Excluir "${name}" e todos os perfis?`)) return;
    const result = await deleteClient(id);
    if (result.success) {
      toast.success('Excluido!');
      if (expandedClientId === id) { setExpandedClientId(null); setExpandedClient(null); }
      await loadClients();
    } else {
      toast.error(result.error || 'Erro');
    }
  };

  const handleCreateProfile = async () => {
    if (!newProfileName.trim()) { toast.error('Nome obrigatorio'); return; }
    if (!expandedClientId) return;
    setCreating(true);
    const result = await createProfile(
      expandedClientId,
      newProfileName.trim(),
      newProfileHost.trim(),
      newProfilePlatform,
      { ...DEFAULT_BUILD_CONFIG, configName: newProfileName.trim(), host: newProfileHost.trim(), platform: newProfilePlatform as any }
    );
    if (result.success) {
      toast.success(`Perfil "${newProfileName.trim()}" criado!`);
      setShowNewProfileModal(false);
      setNewProfileName('');
      setNewProfileHost('');
      await handleExpandClient(expandedClientId);
      await loadClients();
    } else {
      toast.error(result.error || 'Erro');
    }
    setCreating(false);
  };

  const handleRenameProfile = async (clientId: string, profileId: string) => {
    if (!editProfileName.trim()) { toast.error('Nome obrigatorio'); return; }
    const result = await renameProfile(clientId, profileId, editProfileName.trim());
    if (result.success) {
      toast.success('Renomeado!');
      setEditingProfileId(null);
      await handleExpandClient(clientId);
    } else {
      toast.error(result.error || 'Erro');
    }
  };

  const handleDeleteProfile = async (clientId: string, profileId: string, name: string) => {
    if (!confirm(`Excluir perfil "${name}" e todas as versoes?`)) return;
    const result = await deleteProfile(clientId, profileId);
    if (result.success) {
      toast.success('Perfil excluido!');
      await handleExpandClient(clientId);
      await loadClients();
    } else {
      toast.error(result.error || 'Erro');
    }
  };

  return (
    <main className="min-h-screen p-4 md:p-8">
      <div className="max-w-5xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <div className="flex items-center gap-3">
            <button onClick={() => router.push('/')} className="btn-secondary">
              <i className="fas fa-arrow-left mr-2"></i>
              Voltar
            </button>
            <h1 className="text-2xl font-bold text-white flex items-center gap-2">
              <i className="fas fa-users text-primary"></i>
              Gerenciar Clientes
            </h1>
          </div>
          <div className="flex items-center gap-3">
            {canEdit() && (
              <button onClick={() => setShowNewClientModal(true)} className="btn-primary">
                <i className="fas fa-plus mr-2"></i>
                Novo Cliente
              </button>
            )}
            <LogoutButton />
          </div>
        </div>

        {/* Search */}
        <div className="section mb-4">
          <div className="flex items-center gap-3">
            <div className="flex-1 relative">
              <i className="fas fa-search absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 text-sm"></i>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Buscar cliente..."
                className="input-field pl-9"
              />
            </div>
            <span className="text-gray-500 text-sm">{filteredClients.length} clientes</span>
          </div>
        </div>

        {/* Client list */}
        <div className="space-y-2">
          {loading ? (
            <div className="section text-center py-8 text-gray-500">
              <i className="fas fa-spinner fa-spin mr-2"></i>Carregando...
            </div>
          ) : filteredClients.length === 0 ? (
            <div className="section text-center py-8 text-gray-500">
              {searchTerm ? 'Nenhum cliente encontrado' : 'Nenhum cliente cadastrado'}
            </div>
          ) : (
            filteredClients.map((client) => (
              <div key={client.id} className="section">
                {/* Client header */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3 flex-1">
                    <button
                      onClick={() => handleExpandClient(client.id)}
                      className="text-gray-400 hover:text-white"
                    >
                      <i className={`fas ${expandedClientId === client.id ? 'fa-chevron-down' : 'fa-chevron-right'} text-xs`}></i>
                    </button>
                    {editingId === client.id ? (
                      <div className="flex gap-2 flex-1">
                        <input
                          type="text"
                          value={editName}
                          onChange={(e) => setEditName(e.target.value)}
                          onKeyDown={(e) => { if (e.key === 'Enter') handleRenameClient(client.id); if (e.key === 'Escape') setEditingId(null); }}
                          className="input-field py-1 px-2 text-sm w-48"
                          autoFocus
                        />
                        <button onClick={() => handleRenameClient(client.id)} className="text-green-400 hover:text-green-300"><i className="fas fa-check"></i></button>
                        <button onClick={() => setEditingId(null)} className="text-gray-400 hover:text-white"><i className="fas fa-times"></i></button>
                      </div>
                    ) : (
                      <span className="text-white font-semibold text-lg">{client.name}</span>
                    )}
                    <span className="text-gray-500 text-xs">{client.profileCount} perfis</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {canEdit() && (
                      <>
                        <button onClick={() => { setEditingId(client.id); setEditName(client.name); }} className="text-blue-400 hover:text-blue-300 text-xs" title="Renomear"><i className="fas fa-pen"></i></button>
                        <button onClick={() => handleDeleteClient(client.id, client.name)} className="text-red-400 hover:text-red-300 text-xs" title="Excluir"><i className="fas fa-trash"></i></button>
                      </>
                    )}
                  </div>
                </div>

                {/* Expanded: profiles */}
                {expandedClientId === client.id && expandedClient && (
                  <div className="mt-3 ml-6 space-y-2">
                    {expandedClient.profiles.length === 0 ? (
                      <p className="text-gray-500 text-sm">Nenhum perfil cadastrado</p>
                    ) : (
                      expandedClient.profiles.map((profile) => (
                        <div key={profile.profileId} className="flex items-center justify-between bg-[#1a1a1a] rounded p-2">
                          <div className="flex items-center gap-3">
                            {editingProfileId === profile.profileId ? (
                              <div className="flex gap-2">
                                <input
                                  type="text"
                                  value={editProfileName}
                                  onChange={(e) => setEditProfileName(e.target.value)}
                                  onKeyDown={(e) => { if (e.key === 'Enter') handleRenameProfile(client.id, profile.profileId); if (e.key === 'Escape') setEditingProfileId(null); }}
                                  className="input-field py-1 px-2 text-sm w-40"
                                  autoFocus
                                />
                                <button onClick={() => handleRenameProfile(client.id, profile.profileId)} className="text-green-400 hover:text-green-300"><i className="fas fa-check"></i></button>
                                <button onClick={() => setEditingProfileId(null)} className="text-gray-400 hover:text-white"><i className="fas fa-times"></i></button>
                              </div>
                            ) : (
                              <>
                                <span className="text-white font-medium">{profile.name}</span>
                                <span className="text-gray-500 text-xs">{profile.platform}</span>
                                {profile.host && <span className="text-gray-600 text-xs">{profile.host}</span>}
                                <span className="text-gray-500 text-xs">{profile.versions.length}v</span>
                              </>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => router.push(`/?clientId=${client.id}&profileId=${profile.profileId}`)}
                              className="text-green-400 hover:text-green-300 text-xs"
                              title="Configurar"
                            >
                              <i className="fas fa-cog"></i>
                            </button>
                            {canEdit() && (
                              <>
                                <button onClick={() => { setEditingProfileId(profile.profileId); setEditProfileName(profile.name); }} className="text-blue-400 hover:text-blue-300 text-xs" title="Renomear"><i className="fas fa-pen"></i></button>
                                <button onClick={() => handleDeleteProfile(client.id, profile.profileId, profile.name)} className="text-red-400 hover:text-red-300 text-xs" title="Excluir"><i className="fas fa-trash"></i></button>
                              </>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                    {canEdit() && (
                      <button
                        onClick={() => setShowNewProfileModal(true)}
                        className="text-blue-400 hover:text-blue-300 text-sm flex items-center gap-1 mt-2"
                      >
                        <i className="fas fa-plus text-xs"></i> Novo Perfil
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        {/* New Client Modal */}
        {showNewClientModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
            <div className="section w-full max-w-md mx-4">
              <h2 className="section-title mb-4"><i className="fas fa-user-plus text-sm"></i>Novo Cliente</h2>
              <label className="input-label">Nome do cliente</label>
              <input type="text" value={newClientName} onChange={(e) => setNewClientName(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') handleCreateClient(); }} placeholder="Ex: NextCoreTI" className="input-field mb-4" autoFocus />
              <div className="flex gap-2 justify-end">
                <button onClick={() => { setShowNewClientModal(false); setNewClientName(''); }} className="btn-secondary">Cancelar</button>
                <button onClick={handleCreateClient} disabled={creating} className="btn-primary">
                  {creating ? <><i className="fas fa-spinner fa-spin mr-2"></i>Criando...</> : <><i className="fas fa-plus mr-2"></i>Criar</>}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* New Profile Modal */}
        {showNewProfileModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
            <div className="section w-full max-w-md mx-4">
              <h2 className="section-title mb-4"><i className="fas fa-layer-group text-sm"></i>Novo Perfil</h2>
              <label className="input-label">Nome do perfil</label>
              <input type="text" value={newProfileName} onChange={(e) => setNewProfileName(e.target.value)} placeholder="Ex: Admin, Cliente, MacOS" className="input-field mb-3" autoFocus />
              <label className="input-label">Host <span className="text-gray-600">(opcional)</span></label>
              <input type="text" value={newProfileHost} onChange={(e) => setNewProfileHost(e.target.value)} placeholder="Ex: rd01.suporte.net.br" className="input-field mb-3" />
              <label className="input-label">Plataforma</label>
              <select value={newProfilePlatform} onChange={(e) => setNewProfilePlatform(e.target.value)} className="input-field mb-4">
                <option value="windows">Windows 64-bit</option>
                <option value="windows-x86">Windows 32-bit</option>
                <option value="linux">Linux</option>
                <option value="macos">macOS</option>
                <option value="android">Android</option>
              </select>
              <div className="flex gap-2 justify-end">
                <button onClick={() => { setShowNewProfileModal(false); setNewProfileName(''); setNewProfileHost(''); }} className="btn-secondary">Cancelar</button>
                <button onClick={handleCreateProfile} disabled={creating} className="btn-primary">
                  {creating ? <><i className="fas fa-spinner fa-spin mr-2"></i>Criando...</> : <><i className="fas fa-plus mr-2"></i>Criar Perfil</>}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
