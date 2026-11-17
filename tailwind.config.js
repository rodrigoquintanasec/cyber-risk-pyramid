/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#090D16', sidebar: '#0D1420', surface: '#121C2B', line: '#243247',
        accent: '#22D3EE', ink: '#E5EDF7', mute: '#94A3B8',
      },
      fontFamily: { sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'] },
    },
  },
  plugins: [],
}
