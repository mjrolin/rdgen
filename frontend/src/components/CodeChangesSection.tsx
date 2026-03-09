'use client';

import { BuildConfig } from '@/types';

interface CodeChangesSectionProps {
  config: BuildConfig;
  onChange: (updates: Partial<BuildConfig>) => void;
}

export default function CodeChangesSection({ config, onChange }: CodeChangesSectionProps) {
  return (
    <div className="section">
      <h2 className="section-title">
        <i className="fas fa-code text-sm"></i>
        Code Changes
      </h2>

      <div className="checkbox-group">
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.cycleMonitor}
            onChange={(e) => onChange({ cycleMonitor: e.target.checked })}
          />
          <span>Cycle monitors button</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.xOffline}
            onChange={(e) => onChange({ xOffline: e.target.checked })}
          />
          <span>X for offline devices</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.removeNewVersionNotif}
            onChange={(e) => onChange({ removeNewVersionNotif: e.target.checked })}
          />
          <span>Remove version notif</span>
        </label>
      </div>
    </div>
  );
}
