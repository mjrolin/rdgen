'use client';

import { BuildConfig } from '@/types';

interface OtherSectionProps {
  config: BuildConfig;
  onChange: (updates: Partial<BuildConfig>) => void;
}

export default function OtherSection({ config, onChange }: OtherSectionProps) {
  return (
    <div className="section">
      <h2 className="section-title">
        <i className="fas fa-cog text-sm"></i>
        Other
      </h2>

      <label className="checkbox-label mb-2">
        <input
          type="checkbox"
          checked={config.removeWallpaper}
          onChange={(e) => onChange({ removeWallpaper: e.target.checked })}
        />
        <span>Remove wallpaper</span>
      </label>

      <h3 className="text-xs font-semibold text-gray-400 mt-4 mb-2">Peer Tabs Visibility</h3>

      <div className="grid grid-cols-2 gap-1">
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.showRecentTab}
            onChange={(e) => onChange({ showRecentTab: e.target.checked })}
          />
          <span>Recent</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.showFavoritesTab}
            onChange={(e) => onChange({ showFavoritesTab: e.target.checked })}
          />
          <span>Favorites</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.showDiscoveredTab}
            onChange={(e) => onChange({ showDiscoveredTab: e.target.checked })}
          />
          <span>Discovered</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.showAddressBookTab}
            onChange={(e) => onChange({ showAddressBookTab: e.target.checked })}
          />
          <span>Address Book</span>
        </label>

        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={config.showMyGroupTab}
            onChange={(e) => onChange({ showMyGroupTab: e.target.checked })}
          />
          <span>My Group</span>
        </label>
      </div>

      <a
        href="https://rustdesk.com/docs/en/self-host/client-configuration/advanced-settings/"
        target="_blank"
        rel="noopener noreferrer"
        className="text-primary hover:underline text-xs mb-2 block mt-4"
      >
        <i className="fas fa-external-link-alt mr-1"></i>
        All settings
      </a>

      <label className="input-label">Default Settings</label>
      <textarea
        value={config.defaultSettings}
        onChange={(e) => onChange({ defaultSettings: e.target.value })}
        className="input-field h-16 font-mono text-xs"
        placeholder="key=value"
      />

      <label className="input-label">Override Settings</label>
      <textarea
        value={config.overrideSettings}
        onChange={(e) => onChange({ overrideSettings: e.target.value })}
        className="input-field h-16 font-mono text-xs"
        placeholder="key=value"
      />
    </div>
  );
}
