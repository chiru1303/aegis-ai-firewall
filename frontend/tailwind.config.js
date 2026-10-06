/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        aegis: {
          bg: '#0B1020',
          surface: '#111827',
          elevated: '#172033',
          hover: '#1D2940',
          border: '#263247',
          'border-subtle': '#1D2738',
          text: '#F4F7FB',
          'text-secondary': '#C0C8D6',
          'text-muted': '#8F9BAD',
          'text-disabled': '#647083',
          accent: '#4F8CFF',
          'accent-hover': '#6A9DFF',
          'accent-focus': '#8BB8FF',
          success: '#35C98A',
          warning: '#E9B44C',
          danger: '#EF626F',
          info: '#58A6E8',
          // Backward compatibility mappings for existing codebase
          dark: '#0B1020',
          darker: '#080C18',
          card: '#111827',
          critical: '#EF626F',
          purple: '#9B72CF',
          cyan: '#58A6E8',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
