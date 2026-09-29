function withOpacity(variableName) {
  return ({ opacityValue }) => {
    if (opacityValue !== undefined) {
      return `rgba(var(${variableName}), ${opacityValue})`;
    }
    return `rgb(var(${variableName}))`;
  };
}

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // dynamic forensic theme (adapts seamlessly to dark & light modes)
        forensic: {
          50: withOpacity('--forensic-50'),
          100: withOpacity('--forensic-100'),
          200: withOpacity('--forensic-200'),
          300: withOpacity('--forensic-300'),
          400: withOpacity('--forensic-400'),
          500: withOpacity('--forensic-500'),
          600: withOpacity('--forensic-600'),
          700: withOpacity('--forensic-700'),
          800: withOpacity('--forensic-800'),
          900: withOpacity('--forensic-900'),
          950: withOpacity('--forensic-950'),
        },
        // Dark backgrounds
        dark: {
          bg: '#0a0f1a',
          card: '#111827',
          border: '#1e293b',
          hover: '#1e293b',
        },
        // Accent colors
        accent: {
          blue: '#3b82f6',
          green: '#10b981',
          amber: '#f59e0b',
          red: '#ef4444',
          purple: '#8b5cf6',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}