/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The API runs on http://127.0.0.1:5080 in development (src/ThreatLock.Api/Properties/launchSettings.json).
// Proxying makes the browser see one origin (the Vite dev server), exactly like production where
// the API serves the built SPA itself. One origin means no CORS configuration and cookies just work.
const api = 'http://127.0.0.1:5080'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': api,
      '/healthz': api,
      '/readyz': api,
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
  },
})
