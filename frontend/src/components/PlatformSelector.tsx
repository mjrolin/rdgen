'use client';

import { Platform, PLATFORMS } from '@/types';

interface PlatformSelectorProps {
  value: Platform;
  onChange: (platform: Platform) => void;
}

export default function PlatformSelector({ value, onChange }: PlatformSelectorProps) {
  return (
    <div className="section">
      <h2 className="text-white text-xl font-bold mb-4 flex items-center gap-2">
        <i className="fas fa-desktop"></i>
        Select Platform
      </h2>
      <div className="flex justify-around mb-4">
        {PLATFORMS.map((platform) => (
          <div
            key={platform.value}
            className="relative cursor-pointer"
            onClick={() => onChange(platform.value)}
          >
            <i
              className={`${platform.icon} platform-icon ${
                value === platform.value ? 'active' : ''
              }`}
            ></i>
            {platform.value === 'windows' && (
              <span className="absolute -bottom-1 -right-1 text-xs font-bold text-white">
                64
              </span>
            )}
            {platform.value === 'windows-x86' && (
              <span className="absolute -bottom-1 -right-1 text-xs font-bold text-white">
                32
              </span>
            )}
          </div>
        ))}
      </div>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as Platform)}
        className="input-field"
      >
        {PLATFORMS.map((platform) => (
          <option key={platform.value} value={platform.value}>
            {platform.label}
          </option>
        ))}
      </select>
    </div>
  );
}
