'use client';

import { useState } from 'react';
import { v4 as uuidv4 } from 'uuid';
import toast from 'react-hot-toast';
import { BuildConfig, DEFAULT_BUILD_CONFIG, BuildJob, ConfigTemplate, TemplateType } from '@/types';
import { startBuild } from '@/lib/api';
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
import BuildProgress from '@/components/BuildProgress';
import { LogoutButton } from '@/components/AuthGuard';

export default function Home() {
  const [config, setConfig] = useState<BuildConfig>(DEFAULT_BUILD_CONFIG);
  const [isBuilding, setIsBuilding] = useState(false);
  const [currentJob, setCurrentJob] = useState<BuildJob | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<TemplateType | null>(null);

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

    const result = await startBuild({
      ...config,
      filename: config.filename || config.configName,
    });

    if (result.success && result.data) {
      setCurrentJob(result.data);
      toast.success('Build started!');
    } else {
      toast.error(result.error || 'Failed to start build');
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

          <div className="max-w-5xl mx-auto">
            <div className="section text-center py-3">
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
                    Generate Client
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
