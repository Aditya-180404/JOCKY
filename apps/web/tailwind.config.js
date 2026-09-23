/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // TraceForge dark theme
        forensic: {
          50: '#f0f4f8',
          100: '#d9e2ec',
          200: '#bcccdc',
          300: '#9fb3c8',
          400: '#829ab1',
          500: '#627d98',
          600: '#486581',
          700: '#334e68',
          800: '#243b53',
          900: '#102a43',
          950: '#0c1e35',
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