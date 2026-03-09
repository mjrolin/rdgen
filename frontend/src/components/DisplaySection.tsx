'use client';

import { BuildConfig, CodecPreference, DisplayMode } from '@/types';

interface DisplaySectionProps {
  config: BuildConfig;
  onChange: (updates: Partial<BuildConfig>) => void;
}

export default function DisplaySection({ config, onChange }: DisplaySectionProps) {
  return (
    <div className="section">
      <h2 className="section-title">
        <i className="fas fa-desktop text-sm"></i>
        Display Settings
      </h2>

      <div className="grid grid-cols-2 gap-3 mb-3">
        <div>
          <label className="input-label">
            Custom Image Quality
            <span className="text-xs text-gray-400 ml-1">({config.customImageQuality}%)</span>
          </label>
          <input
            type="range"
            min="0"
            max="100"
            value={config.customImageQuality}
            onChange={(e) => onChange({ customImageQuality: parseInt(e.target.value) })}
            className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer"
          />
          <div className="flex justify-between text-xs text-gray-500 mt-1">
            <span>Baixa (0)</span>
            <span>Alta (100)</span>
          </div>
        </div>

        <div>
          <label className="input-label">FPS (Frames per Second)</label>
          <select
            value={config.fps}
            onChange={(e) => onChange({ fps: parseInt(e.target.value) })}
            className="input-field"
          >
            <option value="15">15 FPS</option>
            <option value="30">30 FPS</option>
            <option value="60">60 FPS</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 mb-3">
        <div>
          <label className="input-label">Codec Preference</label>
          <select
            value={config.codecPreference}
            onChange={(e) => onChange({ codecPreference: e.target.value as CodecPreference })}
            className="input-field"
          >
            <option value="vp9">VP9 (Recomendado)</option>
            <option value="vp8">VP8</option>
            <option value="h264">H264</option>
            <option value="h265">H265/HEVC</option>
            <option value="av1">AV1</option>
          </select>
        </div>

        <div>
          <label className="input-label">Display Mode</label>
          <select
            value={config.displayMode}
            onChange={(e) => onChange({ displayMode: e.target.value as DisplayMode })}
            className="input-field"
          >
            <option value="adaptive">Adaptive (Ajusta automaticamente)</option>
            <option value="original">Original (Resolução nativa)</option>
            <option value="fit">Fit (Ajustar à janela)</option>
          </select>
        </div>
      </div>

      <div className="mb-3">
        <label className="flex items-center cursor-pointer">
          <input
            type="checkbox"
            checked={config.enableHwCodec}
            onChange={(e) => onChange({ enableHwCodec: e.target.checked })}
            className="form-checkbox h-4 w-4 text-blue-600 rounded border-gray-600 bg-gray-700"
          />
          <span className="ml-2 text-sm text-gray-300">
            Enable Hardware Codec
            <span className="text-xs text-gray-500 ml-1">(GPU aceleração para melhor performance)</span>
          </span>
        </label>
      </div>

      <div className="bg-blue-900/20 border border-blue-700/30 rounded-md p-3">
        <div className="flex items-start">
          <i className="fas fa-info-circle text-blue-400 mt-0.5 mr-2"></i>
          <div className="text-xs text-blue-300">
            <strong>Dicas:</strong>
            <ul className="mt-1 ml-4 list-disc space-y-1">
              <li>VP9 oferece melhor qualidade com menor uso de banda</li>
              <li>Hardware Codec usa GPU para melhor performance</li>
              <li>60 FPS é ideal para trabalhos gráficos e animações</li>
              <li>Qualidade de imagem alta (80-100) consome mais banda</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
