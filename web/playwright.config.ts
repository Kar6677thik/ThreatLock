import { defineConfig, devices } from '@playwright/test'

// End-to-end smoke test (SPEC §17): a real browser against the running stack, i.e. the API, the
// Worker and the Vite dev server (which proxies /api). Start them first; see docs/development.md.
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  retries: 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:5173',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
