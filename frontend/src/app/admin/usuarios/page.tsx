'use client';

import { useState, useEffect } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { useRouter } from 'next/navigation';
import { LogoutButton } from '@/components/AuthGuard';
import { isAdmin } from '@/lib/permissions';

interface User {
  id: string;
  username: string;
  name: string;
  role: string;
  isActive: boolean;
  lastLogin: string | null;
  createdAt: string;
}

const ROLES = [
  { value: 'admin', label: 'Administrador' },
  { value: 'operador', label: 'Operador' },
  { value: 'construtor', label: 'Construtor' },
  { value: 'visualizador', label: 'Visualizador' },
];

function roleLabel(role: string): string {
  return ROLES.find((r) => r.value === role)?.label || role;
}

function formatDate(iso: string | null): string {
  if (!iso) return 'Nunca';
  return new Date(iso).toLocaleString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export default function AdminUsuariosPage() {
  const router = useRouter();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNewModal, setShowNewModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [saving, setSaving] = useState(false);

  // New user fields
  const [newName, setNewName] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('operador');

  // Edit user fields
  const [editUser, setEditUser] = useState<User | null>(null);
  const [editName, setEditName] = useState('');
  const [editRole, setEditRole] = useState('');
  const [editPassword, setEditPassword] = useState('');

  useEffect(() => {
    if (!isAdmin()) {
      toast.error('Acesso restrito a administradores');
      router.push('/');
      return;
    }
    loadUsers();
  }, []);

  const api = axios.create({ baseURL: '/api' });
  api.interceptors.request.use((config) => {
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('rdgen_token');
      if (token) config.headers['X-Session-Token'] = token;
    }
    return config;
  });

  const loadUsers = async () => {
    setLoading(true);
    try {
      const res = await api.get('/admin/users');
      if (res.data.success) {
        setUsers(res.data.data);
      } else {
        toast.error(res.data.error || 'Erro ao carregar usuarios');
      }
    } catch (err: any) {
      toast.error(err.response?.data?.error || 'Erro ao carregar usuarios');
    }
    setLoading(false);
  };

  const handleCreate = async () => {
    if (!newName.trim()) { toast.error('Nome obrigatorio'); return; }
    if (!newUsername.trim()) { toast.error('Username obrigatorio'); return; }
    if (!newPassword.trim()) { toast.error('Senha obrigatoria'); return; }
    setSaving(true);
    try {
      const res = await api.post('/admin/users', {
        username: newUsername.trim(),
        password: newPassword,
        name: newName.trim(),
        role: newRole,
      });
      if (res.data.success) {
        toast.success('Usuario criado com sucesso!');
        setShowNewModal(false);
        resetNewFields();
        await loadUsers();
      } else {
        toast.error(res.data.error || 'Erro ao criar usuario');
      }
    } catch (err: any) {
      toast.error(err.response?.data?.error || 'Erro ao criar usuario');
    }
    setSaving(false);
  };

  const handleOpenEdit = (user: User) => {
    setEditUser(user);
    setEditName(user.name);
    setEditRole(user.role);
    setEditPassword('');
    setShowEditModal(true);
  };

  const handleSaveEdit = async () => {
    if (!editUser) return;
    if (!editName.trim()) { toast.error('Nome obrigatorio'); return; }
    setSaving(true);
    const body: any = { name: editName.trim(), role: editRole };
    if (editPassword.trim()) body.password = editPassword;
    try {
      const res = await api.patch(`/admin/users/${editUser.id}`, body);
      if (res.data.success) {
        toast.success('Usuario atualizado!');
        setShowEditModal(false);
        setEditUser(null);
        await loadUsers();
      } else {
        toast.error(res.data.error || 'Erro ao atualizar usuario');
      }
    } catch (err: any) {
      toast.error(err.response?.data?.error || 'Erro ao atualizar usuario');
    }
    setSaving(false);
  };

  const handleToggleActive = async (user: User) => {
    const action = user.isActive ? 'desativar' : 'ativar';
    if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} usuario "${user.name}"?`)) return;
    try {
      const res = await api.patch(`/admin/users/${user.id}`, { isActive: !user.isActive });
      if (res.data.success) {
        toast.success(`Usuario ${action === 'desativar' ? 'desativado' : 'ativado'}!`);
        await loadUsers();
      } else {
        toast.error(res.data.error || `Erro ao ${action} usuario`);
      }
    } catch (err: any) {
      toast.error(err.response?.data?.error || `Erro ao ${action} usuario`);
    }
  };

  const resetNewFields = () => {
    setNewName('');
    setNewUsername('');
    setNewPassword('');
    setNewRole('operador');
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
              <i className="fas fa-user-shield text-primary"></i>
              Gerenciar Usuarios
            </h1>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => setShowNewModal(true)} className="btn-primary">
              <i className="fas fa-plus mr-2"></i>
              Novo Usuario
            </button>
            <LogoutButton />
          </div>
        </div>

        {/* Table */}
        <div className="section">
          {loading ? (
            <div className="text-center py-8 text-gray-500">
              <i className="fas fa-spinner fa-spin mr-2"></i>Carregando...
            </div>
          ) : users.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              Nenhum usuario cadastrado
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-3 text-gray-400 font-medium">Nome</th>
                    <th className="text-left py-3 px-3 text-gray-400 font-medium">Username</th>
                    <th className="text-left py-3 px-3 text-gray-400 font-medium">Papel</th>
                    <th className="text-left py-3 px-3 text-gray-400 font-medium">Status</th>
                    <th className="text-left py-3 px-3 text-gray-400 font-medium">Ultimo Login</th>
                    <th className="text-right py-3 px-3 text-gray-400 font-medium">Acoes</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id} className="border-b border-gray-800 hover:bg-[#1a1a1a]">
                      <td className="py-3 px-3 text-white font-medium">{user.name}</td>
                      <td className="py-3 px-3 text-gray-300">{user.username}</td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded text-xs font-medium bg-blue-900/50 text-blue-300">
                          {roleLabel(user.role)}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        {user.isActive ? (
                          <span className="px-2 py-0.5 rounded text-xs font-medium bg-green-900/50 text-green-300">
                            Ativo
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-xs font-medium bg-red-900/50 text-red-300">
                            Inativo
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 text-gray-500 text-xs">{formatDate(user.lastLogin)}</td>
                      <td className="py-3 px-3 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleOpenEdit(user)}
                            className="text-blue-400 hover:text-blue-300 text-xs"
                            title="Editar"
                          >
                            <i className="fas fa-pen"></i>
                          </button>
                          <button
                            onClick={() => handleToggleActive(user)}
                            className={user.isActive ? 'text-red-400 hover:text-red-300 text-xs' : 'text-green-400 hover:text-green-300 text-xs'}
                            title={user.isActive ? 'Desativar' : 'Ativar'}
                          >
                            <i className={user.isActive ? 'fas fa-user-slash' : 'fas fa-user-check'}></i>
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

        {/* New User Modal */}
        {showNewModal && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
            <div className="section w-full max-w-md mx-4">
              <h2 className="section-title mb-4">
                <i className="fas fa-user-plus text-sm"></i>Novo Usuario
              </h2>
              <label className="input-label">Nome</label>
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="Nome completo"
                className="input-field mb-3"
                autoFocus
              />
              <label className="input-label">Username</label>
              <input
                type="text"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                placeholder="nome.usuario"
                className="input-field mb-3"
              />
              <label className="input-label">Senha</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Minimo 6 caracteres"
                className="input-field mb-3"
              />
              <label className="input-label">Papel</label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                className="input-field mb-4"
              >
                {ROLES.map((r) => (
                  <option key={r.value} value={r.value}>{r.label}</option>
                ))}
              </select>
              <div className="flex gap-2 justify-end">
                <button onClick={() => { setShowNewModal(false); resetNewFields(); }} className="btn-secondary">
                  Cancelar
                </button>
                <button onClick={handleCreate} disabled={saving} className="btn-primary">
                  {saving ? (
                    <><i className="fas fa-spinner fa-spin mr-2"></i>Criando...</>
                  ) : (
                    <><i className="fas fa-plus mr-2"></i>Criar</>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Edit User Modal */}
        {showEditModal && editUser && (
          <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
            <div className="section w-full max-w-md mx-4">
              <h2 className="section-title mb-4">
                <i className="fas fa-user-edit text-sm"></i>Editar Usuario
              </h2>
              <label className="input-label">Nome</label>
              <input
                type="text"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                className="input-field mb-3"
                autoFocus
              />
              <label className="input-label">Username</label>
              <input
                type="text"
                value={editUser.username}
                disabled
                className="input-field mb-3 opacity-60 cursor-not-allowed"
              />
              <label className="input-label">Nova Senha <span className="text-gray-600">(deixe vazio para manter)</span></label>
              <input
                type="password"
                value={editPassword}
                onChange={(e) => setEditPassword(e.target.value)}
                placeholder="Nova senha"
                className="input-field mb-3"
              />
              <label className="input-label">Papel</label>
              <select
                value={editRole}
                onChange={(e) => setEditRole(e.target.value)}
                className="input-field mb-4"
              >
                {ROLES.map((r) => (
                  <option key={r.value} value={r.value}>{r.label}</option>
                ))}
              </select>
              <div className="flex gap-2 justify-end">
                <button onClick={() => { setShowEditModal(false); setEditUser(null); }} className="btn-secondary">
                  Cancelar
                </button>
                <button onClick={handleSaveEdit} disabled={saving} className="btn-primary">
                  {saving ? (
                    <><i className="fas fa-spinner fa-spin mr-2"></i>Salvando...</>
                  ) : (
                    <><i className="fas fa-save mr-2"></i>Salvar</>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
