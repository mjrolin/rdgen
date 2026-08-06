'use client';

import { useState, useEffect } from 'react';
import { ClientListItem } from '@/types';
import { listClients, deleteClient, renameClient } from '@/lib/api';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';
import { LogoutButton } from '@/components/AuthGuard';

export default function ClientesPage() {
  const [clients, setClients] = useState<ClientListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const router = useRouter();

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

  const filteredClients = clients.filter((c) =>
    c.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.host.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleRename = async (id: string) => {
    if (!editName.trim()) {
      toast.error('Nome nao pode ser vazio');
      return;
    }
    const result = await renameClient(id, editName.trim());
    if (result.success) {
      toast.success('Cliente renomeado!');
      setEditingId(null);
      await loadClients();
    } else {
      toast.error(result.error || 'Erro ao renomear');
    }
  };

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Tem certeza que deseja excluir "${name}"? Todas as versoes serao perdidas.`)) {
      return;
    }
    const result = await deleteClient(id);
    if (result.success) {
      toast.success('Cliente excluido!');
      await loadClients();
    } else {
      toast.error(result.error || 'Erro ao excluir');
    }
  };

  return (
    <main className="min-h-screen p-4 md:p-8">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
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
          <LogoutButton />
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
                placeholder="Buscar por nome ou host..."
                className="input-field pl-9"
              />
            </div>
            <span className="text-gray-500 text-sm">
              {filteredClients.length} de {clients.length} clientes
            </span>
          </div>
        </div>

        {/* Table */}
        <div className="section">
          {loading ? (
            <div className="text-center py-8 text-gray-500">
              <i className="fas fa-spinner fa-spin mr-2"></i>
              Carregando...
            </div>
          ) : filteredClients.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              {searchTerm ? 'Nenhum cliente encontrado' : 'Nenhum cliente cadastrado'}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#333] text-gray-400">
                    <th className="text-left py-2 px-3">Nome</th>
                    <th className="text-left py-2 px-3">Host</th>
                    <th className="text-center py-2 px-3">Versoes</th>
                    <th className="text-left py-2 px-3">Ultima atualizacao</th>
                    <th className="text-right py-2 px-3">Acoes</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredClients.map((client) => (
                    <tr key={client.id} className="border-b border-[#222] hover:bg-[#1a1a1a]">
                      <td className="py-2 px-3">
                        {editingId === client.id ? (
                          <div className="flex gap-2">
                            <input
                              type="text"
                              value={editName}
                              onChange={(e) => setEditName(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') handleRename(client.id);
                                if (e.key === 'Escape') setEditingId(null);
                              }}
                              className="input-field py-1 px-2 text-sm"
                              autoFocus
                            />
                            <button onClick={() => handleRename(client.id)} className="text-green-400 hover:text-green-300">
                              <i className="fas fa-check"></i>
                            </button>
                            <button onClick={() => setEditingId(null)} className="text-gray-400 hover:text-white">
                              <i className="fas fa-times"></i>
                            </button>
                          </div>
                        ) : (
                          <span className="text-white font-medium">{client.name}</span>
                        )}
                      </td>
                      <td className="py-2 px-3 text-gray-400">{client.host}</td>
                      <td className="py-2 px-3 text-center text-gray-400">{client.versionCount}</td>
                      <td className="py-2 px-3 text-gray-400">
                        {new Date(client.updatedAt).toLocaleDateString('pt-BR')}{' '}
                        {new Date(client.updatedAt).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td className="py-2 px-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => {
                              setEditingId(client.id);
                              setEditName(client.name);
                            }}
                            className="text-blue-400 hover:text-blue-300 text-xs"
                            title="Renomear"
                          >
                            <i className="fas fa-pen"></i>
                          </button>
                          <button
                            onClick={() => handleDelete(client.id, client.name)}
                            className="text-red-400 hover:text-red-300 text-xs"
                            title="Excluir"
                          >
                            <i className="fas fa-trash"></i>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
