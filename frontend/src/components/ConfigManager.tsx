'use client';

import { useRef } from 'react';
import { BuildConfig, DEFAULT_BUILD_CONFIG } from '@/types';

interface ConfigManagerProps {
  config: BuildConfig;
  onLoad: (config: BuildConfig) => void;
}

// Convert Bryan's rdgen format to our format
function convertBryanFormat(old: Record<string, unknown>): BuildConfig {
  // Check if it's Bryan's format by looking for his specific fields
  const isBryanFormat = 'compname' in old || 'serverIP' in old || 'exename' in old || 'installation' in old;

  if (!isBryanFormat) {
    // Already in our format
    return old as unknown as BuildConfig;
  }

  // Helper to check boolean-like values
  const toBool = (val: unknown): boolean =>
    val === true || val === 'True' || val === 'on' || val === 'Y';

  // Clean base64 - remove data:image prefix if present
  const cleanBase64 = (val: unknown): string => {
    if (!val || typeof val !== 'string') return '';
    if (val.startsWith('data:')) {
      return val.split(',')[1] || '';
    }
    return val;
  };

  // Map direction
  const mapDirection = (dir: unknown): 'Both' | 'Incoming' | 'Outgoing' => {
    if (dir === 'both' || dir === 'Both') return 'Both';
    if (dir === 'incoming' || dir === 'Incoming') return 'Incoming';
    if (dir === 'outgoing' || dir === 'Outgoing') return 'Outgoing';
    return 'Both';
  };

  return {
    ...DEFAULT_BUILD_CONFIG,
    platform: (old.platform as BuildConfig['platform']) || 'windows',
    version: (old.version as BuildConfig['version']) || '1.4.4',
    configName: (old.configName || old.exename || '') as string,
    appName: (old.appname || old.appName || '') as string,
    filename: (old.exename || old.filename || '') as string,
    connectionDirection: mapDirection(old.connectionDirection || old.direction),
    disableInstallation: old.installation !== 'installationY',
    disableSettings: old.settings !== 'settingsY',
    host: (old.host || old.serverIP || '') as string,
    key: (old.key || '') as string,
    apiServer: (old.apiServer || '') as string,
    urlLink: (old.urlLink || '') as string,
    downloadLink: (old.downloadLink || '') as string,
    companyName: (old.companyName || old.compname || '') as string,
    approveMode: (old.passApproveMode || old.approveMode || 'password-click') as BuildConfig['approveMode'],
    permanentPassword: (old.permanentPassword || '') as string,
    denyLanDiscovery: toBool(old.denyLanDiscovery || old.denyLan),
    enableDirectIp: toBool(old.enableDirectIp || old.enableDirectIP),
    autoCloseInactivity: toBool(old.autoCloseInactivity || old.autoClose),
    allowHideConnectionWindow: toBool(old.allowHideConnectionWindow || old.hidecm),
    iconBase64: cleanBase64(old.iconBase64 || old.iconbase64),
    logoBase64: cleanBase64(old.logoBase64 || old.logobase64),
    theme: (old.theme as BuildConfig['theme']) || 'system',
    themeMode: (old.themeMode || old.themeDorO || 'default') as BuildConfig['themeMode'],
    permissionsMode: (old.permissionsMode || old.permissionsDorO || 'default') as BuildConfig['permissionsMode'],
    permissionsType: (old.permissionsType || 'full') as BuildConfig['permissionsType'],
    enableKeyboard: toBool(old.enableKeyboard),
    enableClipboard: toBool(old.enableClipboard),
    enableFileTransfer: toBool(old.enableFileTransfer),
    enableAudio: toBool(old.enableAudio),
    enableTcp: toBool(old.enableTcp || old.enableTCP),
    enableRemoteRestart: toBool(old.enableRemoteRestart),
    enableRecording: toBool(old.enableRecording),
    enableBlockingInput: toBool(old.enableBlockingInput),
    enableRemoteConfig: toBool(old.enableRemoteConfig || old.enableRemoteModi),
    enablePrinter: toBool(old.enablePrinter),
    enableCamera: toBool(old.enableCamera),
    enableTerminal: toBool(old.enableTerminal),
    cycleMonitor: toBool(old.cycleMonitor),
    xOffline: toBool(old.xOffline),
    removeNewVersionNotif: toBool(old.removeNewVersionNotif),
    delayFix: toBool(old.delayFix),
    removeWallpaper: toBool(old.removeWallpaper),
    defaultSettings: (old.defaultSettings || old.defaultManual || '') as string,
    overrideSettings: (old.overrideSettings || old.overrideManual || '') as string,
  };
}

export default function ConfigManager({ config, onLoad }: ConfigManagerProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleSave = () => {
    if (!config.configName) {
      alert('Please enter a configuration name first');
      return;
    }

    const json = JSON.stringify(config, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${config.configName}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleLoad = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const rawConfig = JSON.parse(event.target?.result as string);
        // Convert from Bryan's format if needed
        const loadedConfig = convertBryanFormat(rawConfig);
        onLoad(loadedConfig);
      } catch {
        alert('Invalid configuration file');
      }
    };
    reader.readAsText(file);

    // Reset input to allow loading same file again
    e.target.value = '';
  };

  return (
    <div className="fixed top-4 left-4 z-50">
      <div className="section">
        <h3 className="text-white font-bold mb-3 flex items-center gap-2">
          <i className="fas fa-save"></i>
          Save/Load Config
        </h3>
        <div className="flex gap-2">
          <button onClick={handleSave} className="btn-secondary text-sm">
            <i className="fas fa-download mr-1"></i>
            Save
          </button>
          <button onClick={handleLoad} className="btn-secondary text-sm">
            <i className="fas fa-upload mr-1"></i>
            Load
          </button>
        </div>
        <input
          ref={fileInputRef}
          type="file"
          accept=".json"
          onChange={handleFileChange}
          className="hidden"
        />
      </div>
    </div>
  );
}
