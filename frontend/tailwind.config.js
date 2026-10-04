/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#0d1117',
        panel: '#12161f',
        panel2: '#181d29',
        line: '#242b3a',
        mist: '#8b93a7',
        signal: '#5fd0b3',
        alert: '#e8a33d',
        danger: '#e5637a',
        wire: '#4f8cff',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['IBM Plex Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
    },
  },
  plugins: [],
}
