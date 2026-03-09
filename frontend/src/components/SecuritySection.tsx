'use client';

import { BuildConfig, ApproveMode } from '@/types';

interface SecuritySectionProps {
  config: BuildConfig;
  onChange: (updates: Partial<BuildConfig>) => void;
}

export default function SecuritySection({ config, onChange }: SecuritySectionProps) {
  return (
    <div className="section">
      <h2 className="section-title">
        <i className="fas fa-shield-alt text-sm"></i>
        Security
      </h2>

      <label className="input-label">Approve Mode</label>
      <select
        value={config.approveMode}
        onChange={(e) => onChange({ approveMode: e.target.value as ApproveMode })}
        className="input-field"
      >
        <option value="password-click">Password + Click</option>
        <option value="password">Password Only</option>
        <option value="click">Click Only</option>
      </select>

      {config.allowHideConnectionWindow && (
        <p className="text-yellow-500 text-xs mt-1 mb-1 animate-pulse">
          Set a permanent password to hide connection window.
        </p>
      )}

      <label className="input-label">Permanent Password</label>
      <input
        type="password"
        value={config.permanentPassword}
        onChange={(e) => onChange({ permanentPassword: e.target.value })}
        className="input-field"
        placeholder="Leave empty to skip"
      />
      <span className="text-gray-500 text-xs">* Can be changed by client</span>

      <div className="mt-3 checkbox-group">
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.denyLanDiscovery}
            onChange={(e) => onChange({ denyLanDiscovery: e.target.checked })}
          />
          <span>Deny LAN discovery</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.enableDirectIp}
            onChange={(e) => onChange({ enableDirectIp: e.target.checked })}
          />
          <span>Enable direct IP</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.autoCloseInactivity}
            onChange={(e) => onChange({ autoCloseInactivity: e.target.checked })}
          />
          <span>Auto close inactive</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.allowHideConnectionWindow}
            onChange={(e) => {
              const checked = e.target.checked;
              const updates: Partial<BuildConfig> = {
                allowHideConnectionWindow: checked,
              };
              if (checked) {
                updates.approveMode = 'password';
              }
              onChange(updates);
            }}
          />
          <span>Hide connection window</span>
        </label>
      </div>
    </div>
  );
}
