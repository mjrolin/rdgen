'use client';

import { useState } from 'react';
import { v4 as uuidv4 } from 'uuid';
import toast from 'react-hot-toast';
import { BuildConfig, DEFAULT_BUILD_CONFIG, BuildJob, ConfigTemplate, TemplateType } from '@/types';
import { startBuild, createClient, addClientVersion } from '@/lib/api';
import PlatformSelector from '@/components/PlatformSelector';
import TemplateSelector from '@/components/TemplateSelector';
import GeneralSection from '@/components/GeneralSection';
import ServerSection from '@/components/ServerSection';
import SecuritySection from '@/components/SecuritySection';
import VisualSection from '@/components/VisualSection';
import PermissionsSection from '@/components/PermissionsSection';
import CodeChangesSection from '@/components/CodeChangesSection';
import OtherSection from '@/components/OtherSection';
import DisplaySection from '@/components/DisplaySection';
import ConfigManager from '@/components/ConfigManager';
import ClientSelector from '@/components/ClientSelector';
import BuildProgress from '@/components/BuildProgress';
import { LogoutButton } from '@/components/AuthGuard';

export default function Home() {
  const [config, setConfig] = useState<BuildConfig>(DEFAULT_BUILD_CONFIG);
  const [isBuilding, setIsBuilding] = useState(false);
  const [currentJob, setCurrentJob] = useState<BuildJob | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<TemplateType | null>(null);
  const [selectedClientId, setSelectedClientId] = useState<string | null>(null);
  const [clientList, setClientList] = useState<{id: string; name: string}[]>([]);

  const updateConfig = (updates: Partial<BuildConfig>) => {
    setConfig((prev) => ({ ...prev, ...updates }));
  };

  const handleTemplateSelect = (template: ConfigTemplate) => {
    setSelectedTemplate(template.id);
    // Merge template config with current config, preserving server settings and platform
    setConfig((prev) => ({
      ...DEFAULT_BUILD_CONFIG,
      ...template.config,
      platform: prev.platform,
      version: prev.version,
      host: prev.host,
      key: prev.key,
      apiServer: prev.apiServer,
      urlLink: prev.urlLink,
      downloadLink: prev.downloadLink,
      companyName: prev.companyName,
      iconBase64: prev.iconBase64,
      logoBase64: prev.logoBase64,
    }));
    toast.success(`Template "${template.name}" aplicado!`);
  };

  const validateConfig = (): string | null => {
    if (!config.configName || config.configName.trim() === '') {
      return 'Configuration name is required';
    }
    if (!config.host && !config.key) {
      // Allow building without server config (will use RustDesk defaults)
    }
    return null;
  };

  const handleGenerate = async () => {
    const error = validateConfig();
    if (error) {
      toast.error(error);
      return;
    }

    setIsBuilding(true);
    setCurrentJob(null);

    const buildConfig = {
      ...config,
      filename: config.filename || config.configName,
    };

    // Auto-save client profile (fire-and-forget alongside build)
    const saveProfile = async () => {
      try {
        if (selectedClientId) {
          const result = await addClientVersion(selectedClientId, buildConfig);
          if (result.success) {
            toast.success('Perfil do cliente atualizado', { id: 'profile-save' });
          }
        } else if (config.configName) {
          const result = await createClient(config.configName, config.host, buildConfig);
          if (result.success && result.data) {
            setSelectedClientId(result.data.id);
            toast.success('Perfil de cliente criado', { id: 'profile-save' });
          }
        }
      } catch {
        console.error('Failed to save client profile');
      }
    };

    // Run build and profile save in parallel
    const [buildResult] = await Promise.all([startBuild(buildConfig), saveProfile()]);

    if (buildResult.success && buildResult.data) {
      setCurrentJob(buildResult.data);
      toast.success('Build started!');
    } else {
      toast.error(buildResult.error || 'Failed to start build');
      setIsBuilding(false);
    }
  };

  const handleBuildComplete = (job: BuildJob) => {
    setCurrentJob(job);
    setIsBuilding(false);
    toast.success('Build completed successfully!');
  };

  const handleBuildError = (error: string) => {
    toast.error(error);
    setIsBuilding(false);
  };


  const handleSaveProfile = async () => {
    if (!config.configName) {
      toast.error('Preencha o nome da configuração antes de salvar');
      return;
    }

    try {
      // Find existing client with same name
      const existingClient = clientList.find(
        (c) => c.name === config.configName && c.id !== selectedClientId
      );

      if (selectedClientId) {
        // A client is selected in the dropdown
        const selectedClient = clientList.find((c) => c.id === selectedClientId);

        if (selectedClient && selectedClient.name !== config.configName) {
          // Name changed — ask user what to do
          const choice = window.confirm(
            `O nome mudou de "${selectedClient.name}" para "${config.configName}".\n\n` +
            `OK = Criar novo cliente "${config.configName}"\n` +
            `Cancelar = Atualizar "${selectedClient.name}" com nova versão`
          );

          if (choice) {
            const result = await createClient(config.configName, config.host, config);
            if (result.success && result.data) {
              setSelectedClientId(result.data.id);
              toast.success(`Novo perfil "${config.configName}" criado!`);
            } else {
              toast.error(result.error || 'Erro ao criar perfil');
            }
            return;
          }
        }

        // Update existing selected client
        const result = await addClientVersion(selectedClientId, config);
        if (result.success) {
          toast.success('Perfil do cliente atualizado!');
        } else {
          toast.error(result.error || 'Erro ao atualizar perfil');
        }
      } else if (existingClient) {
        // No client selected but name matches an existing one
        const choice = window.confirm(
          `Já existe um cliente chamado "${config.configName}".\n\n` +
          `OK = Atualizar "${config.configName}" com nova versão\n` +
          `Cancelar = Criar novo cliente com mesmo nome`
        );

        if (choice) {
          const result = await addClientVersion(existingClient.id, config);
          if (result.success) {
            setSelectedClientId(existingClient.id);
            toast.success('Perfil do cliente atualizado!');
          } else {
            toast.error(result.error || 'Erro ao atualizar perfil');
          }
        } else {
          const result = await createClient(config.configName, config.host, config);
          if (result.success && result.data) {
            setSelectedClientId(result.data.id);
            toast.success(`Perfil "${config.configName}" criado!`);
          } else {
            toast.error(result.error || 'Erro ao criar perfil');
          }
        }
      } else {
        // No client selected, no name conflict — create new
        const result = await createClient(config.configName, config.host, config);
        if (result.success && result.data) {
          setSelectedClientId(result.data.id);
          toast.success(`Perfil "${config.configName}" criado!`);
        } else {
          toast.error(result.error || 'Erro ao criar perfil');
        }
      }
    } catch {
      toast.error('Erro ao salvar perfil');
    }
  };

  const handleNewBuild = () => {
    setCurrentJob(null);
    setIsBuilding(false);
  };

  return (
    <main className="min-h-screen p-4 md:p-8">
      {/* Header with logout */}
      <div className="max-w-5xl mx-auto flex justify-between items-center mb-4">
        <a href="/api-docs" className="text-blue-400 hover:text-blue-300 text-sm">
          API Docs
        </a>
        <LogoutButton />
      </div>

      <ConfigManager config={config} onLoad={setConfig} />

      <ClientSelector
        currentConfig={config}
        onConfigLoad={setConfig}
        selectedClientId={selectedClientId}
        onSelectClient={setSelectedClientId}
        onClientListChange={setClientList}
      />

      <h1 className="text-2xl font-bold text-white text-center mb-6 flex items-center justify-center gap-2">
        <i className="fas fa-cogs text-primary text-xl"></i>
        RustDesk Custom Client Builder
      </h1>

      {currentJob ? (
        <div className="max-w-4xl mx-auto">
          <BuildProgress
            jobId={currentJob.id}
            onComplete={handleBuildComplete}
            onError={handleBuildError}
          />
          {(currentJob.status === 'completed' ||
            currentJob.status === 'failed' ||
            currentJob.status === 'cancelled') && (
            <div className="text-center mt-4">
              <button onClick={handleNewBuild} className="btn-secondary">
                <i className="fas fa-plus mr-2"></i>
                Start New Build
              </button>
            </div>
          )}
        </div>
      ) : (
        <>
          <div className="max-w-5xl mx-auto mb-4">
            <PlatformSelector
              value={config.platform}
              onChange={(platform) => updateConfig({ platform })}
            />
          </div>

          <div className="max-w-5xl mx-auto mb-4">
            <TemplateSelector
              selectedTemplate={selectedTemplate}
              onSelect={handleTemplateSelect}
            />
          </div>

          <div className="max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <GeneralSection config={config} onChange={updateConfig} />
            <ServerSection config={config} onChange={updateConfig} />
          </div>

          <div className="max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <SecuritySection config={config} onChange={updateConfig} />
            <VisualSection config={config} onChange={updateConfig} />
          </div>

          <div className="max-w-5xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <PermissionsSection config={config} onChange={updateConfig} />
            <div className="space-y-4">
              <CodeChangesSection config={config} onChange={updateConfig} />
              <OtherSection config={config} onChange={updateConfig} />
            </div>
          </div>

          <div className="max-w-5xl mx-auto mb-4">
            <DisplaySection config={config} onChange={updateConfig} />
          </div>

          {/* Spacer for sticky bar */}
          <div className="h-20"></div>

          {/* Sticky action bar */}
          <div className="fixed bottom-0 left-0 right-0 bg-[#111] border-t border-[#333] shadow-lg z-50">
            <div className="max-w-5xl mx-auto flex items-center justify-between py-3 px-4">
              <div className="flex gap-2">
                <button
                  onClick={handleSaveProfile}
                  className="btn-secondary px-4 py-2"
                >
                  <i className="fas fa-save mr-2"></i>
                  Salvar Perfil
                </button>
              </div>
              <button
                onClick={handleGenerate}
                disabled={isBuilding}
                className="btn-primary px-6 py-2"
              >
                {isBuilding ? (
                  <>
                    <i className="fas fa-spinner fa-spin mr-2"></i>
                    Starting...
                  </>
                ) : (
                  <>
                    <i className="fas fa-rocket mr-2"></i>
                    Gerar Build
                  </>
                )}
              </button>
            </div>
          </div>

        </>
      )}
    </main>
  );
}
