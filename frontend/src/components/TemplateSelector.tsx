'use client';

import { ConfigTemplate, CONFIG_TEMPLATES, BuildConfig, DEFAULT_BUILD_CONFIG, TemplateType } from '@/types';

interface TemplateSelectorProps {
  selectedTemplate: TemplateType | null;
  onSelect: (template: ConfigTemplate) => void;
}

export default function TemplateSelector({ selectedTemplate, onSelect }: TemplateSelectorProps) {
  return (
    <div className="section mb-4">
      <h2 className="section-title">
        <i className="fas fa-layer-group text-sm"></i>
        Escolha um Template
      </h2>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {CONFIG_TEMPLATES.map((template) => (
          <button
            key={template.id}
            onClick={() => onSelect(template)}
            className={`p-4 rounded-lg border-2 transition-all text-left ${
              selectedTemplate === template.id
                ? 'border-primary bg-primary/10'
                : 'border-gray-700 hover:border-gray-500 bg-gray-800/50'
            }`}
          >
            <div className="flex items-center gap-2 mb-2">
              <i className={`${template.icon} ${selectedTemplate === template.id ? 'text-primary' : 'text-gray-400'}`}></i>
              <span className={`font-semibold ${selectedTemplate === template.id ? 'text-primary' : 'text-white'}`}>
                {template.name}
              </span>
            </div>
            <p className="text-xs text-gray-400">{template.description}</p>
          </button>
        ))}
      </div>
    </div>
  );
}
