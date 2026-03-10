/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        dark: { 900: '#0a0a0f', 800: '#12121a', 700: '#1a1a2e' },
        shield: { 500: '#6366f1', 400: '#818cf8', 300: '#a5b4fc' },
        danger: { 500: '#ef4444', 400: '#f87171' },
        warn: { 500: '#f59e0b', 400: '#fbbf24' },
      }
    }
  },
  plugins: []
}