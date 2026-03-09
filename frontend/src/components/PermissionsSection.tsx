'use client';

import { BuildConfig, PermissionMode, PermissionType } from '@/types';

interface PermissionsSectionProps {
  config: BuildConfig;
  onChange: (updates: Partial<BuildConfig>) => void;
}

export default function PermissionsSection({ config, onChange }: PermissionsSectionProps) {
  const handlePermissionTypeChange = (type: PermissionType) => {
    const updates: Partial<BuildConfig> = { permissionsType: type };

    if (type === 'full') {
      updates.enableKeyboard = true;
      updates.enableClipboard = true;
      updates.enableFileTransfer = true;
      updates.enableAudio = true;
      updates.enableTcp = true;
      updates.enableRemoteRestart = true;
      updates.enableRecording = true;
      updates.enableBlockingInput = true;
      updates.enableRemoteConfig = true;
      updates.enablePrinter = true;
      updates.enableCamera = true;
      updates.enableTerminal = true;
    } else if (type === 'view') {
      updates.enableKeyboard = false;
      updates.enableClipboard = false;
      updates.enableFileTransfer = false;
      updates.enableAudio = false;
      updates.enableTcp = false;
      updates.enableRemoteRestart = false;
      updates.enableRecording = false;
      updates.enableBlockingInput = false;
      updates.enableRemoteConfig = false;
      updates.enablePrinter = false;
      updates.enableCamera = false;
      updates.enableTerminal = false;
    }

    onChange(updates);
  };

  const isCustomDisabled = config.permissionsType !== 'custom';

  return (
    <div className="section">
      <h2 className="section-title">
        <i className="fas fa-lock text-sm"></i>
        Permissions
      </h2>

      <div className="grid grid-cols-2 gap-3 mb-3">
        <div>
          <label className="input-label">Mode</label>
          <select
            value={config.permissionsMode}
            onChange={(e) =>
              onChange({ permissionsMode: e.target.value as PermissionMode })
            }
            className="input-field"
          >
            <option value="default">Default</option>
            <option value="override">Override</option>
          </select>
        </div>
        <div>
          <label className="input-label">Type</label>
          <select
            value={config.permissionsType}
            onChange={(e) => handlePermissionTypeChange(e.target.value as PermissionType)}
            className="input-field"
          >
            <option value="full">Full Access</option>
            <option value="view">View Only</option>
            <option value="custom">Custom</option>
          </select>
        </div>
      </div>

      <div className="checkbox-group">
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableKeyboard}
            onChange={(e) => onChange({ enableKeyboard: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Keyboard/mouse</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableClipboard}
            onChange={(e) => onChange({ enableClipboard: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Clipboard</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableFileTransfer}
            onChange={(e) => onChange({ enableFileTransfer: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>File transfer</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableAudio}
            onChange={(e) => onChange({ enableAudio: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Audio</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableTcp}
            onChange={(e) => onChange({ enableTcp: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>TCP tunneling</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableRemoteRestart}
            onChange={(e) => onChange({ enableRemoteRestart: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Remote restart</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableRecording}
            onChange={(e) => onChange({ enableRecording: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Recording</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableBlockingInput}
            onChange={(e) => onChange({ enableBlockingInput: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Block input</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableRemoteConfig}
            onChange={(e) => onChange({ enableRemoteConfig: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Remote config</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enablePrinter}
            onChange={(e) => onChange({ enablePrinter: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Printer</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableCamera}
            onChange={(e) => onChange({ enableCamera: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Camera</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableTerminal}
            onChange={(e) => onChange({ enableTerminal: e.target.checked })}
            disabled={isCustomDisabled}
          />
          <span className={isCustomDisabled ? 'text-gray-600' : ''}>Terminal</span>
        </label>
      </div>
    </div>
  );
}
