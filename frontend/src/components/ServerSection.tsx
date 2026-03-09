'use client';

import { BuildConfig } from '@/types';

interface ServerSectionProps {
  config: BuildConfig;
  onChange: (updates: Partial<BuildConfig>) => void;
}

export default function ServerSection({ config, onChange }: ServerSectionProps) {
  return (
    <div className="section">
      <h2 className="section-title">
        <i className="fas fa-server text-sm"></i>
        Custom Server
      </h2>

      <label className="input-label">Host (Rendezvous Server)</label>
      <input
        type="text"
        value={config.host}
        onChange={(e) => onChange({ host: e.target.value })}
        className="input-field"
        placeholder="rustdesk.example.com"
      />

      <label className="input-label">Key (Public Key)</label>
      <input
        type="text"
        value={config.key}
        onChange={(e) => onChange({ key: e.target.value })}
        className="input-field"
        placeholder="YOUR_PUBLIC_KEY_BASE64"
      />

      <label className="input-label">API Server</label>
      <input
        type="text"
        value={config.apiServer}
        onChange={(e) => onChange({ apiServer: e.target.value })}
        className="input-field"
        placeholder="https://rustdesk.example.com:21114"
      />

      <label className="input-label">Custom URL (links)</label>
      <input
        type="text"
        value={config.urlLink}
        onChange={(e) => onChange({ urlLink: e.target.value })}
        className="input-field"
        placeholder="https://rustdesk.com"
      />

      <label className="input-label">Custom URL (updates)</label>
      <input
        type="text"
        value={config.downloadLink}
        onChange={(e) => onChange({ downloadLink: e.target.value })}
        className="input-field"
        placeholder="https://rustdesk.com/download"
      />

      <label className="input-label">Company Name</label>
      <input
        type="text"
        value={config.companyName}
        onChange={(e) => onChange({ companyName: e.target.value })}
        className="input-field"
        placeholder="Purslane Ltd"
      />
    </div>
  );
}
