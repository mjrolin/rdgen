import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        primary: '#0077ff',
        'primary-hover': '#0066cc',
        dark: {
          100: '#222',
          200: '#111',
          300: '#000',
        },
      },
    },
  },
  plugins: [],
};

export default config;
