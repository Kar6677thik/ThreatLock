import { expect, test } from '@playwright/test'

// The development simulator key (appsettings.Development.json). It only works where Simulation is
// enabled; never set one on anything reachable from the internet (ADR-0007).
const SIM_KEY = process.env.E2E_SIM_KEY ?? 'dev-only-simulator-key-change-me'
const PASSWORD = 'correct horse battery staple'

async function torExit(request: import('@playwright/test').APIRequestContext) {
  if (process.env.E2E_TOR_IP) return process.env.E2E_TOR_IP
  const list = await (await request.get('https://check.torproject.org/torbulkexitlist')).text()
  return list.split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'))!
}

/**
 * The whole loop in a real browser: sign up and use the app, then someone signs in to the same
 * account through a Tor exit. Detector D1 fires, the Worker revokes every session of the user,
 * and the browser's next request lands on the sign-in screen with "You were signed out".
 */
test('a session the Worker revokes signs the browser out', async ({ page, request }) => {
  const email = `e2e-${Date.now()}@e2e.test`

  await page.goto('/')
  await page.getByRole('button', { name: 'Create an organisation' }).click()
  await page.getByLabel('Organisation name').fill('E2E Org')
  await page.getByLabel('Your name').fill('Erin')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Password').fill(PASSWORD)
  await page.getByRole('button', { name: 'Create organisation' }).click()
  await expect(page.getByRole('link', { name: 'My sessions' })).toBeVisible()

  // The attacker: same password, from a Tor exit, out of band.
  const login = await request.post('/api/auth/login', {
    headers: { 'X-Simulator-Key': SIM_KEY, 'X-Simulated-Client-Ip': await torExit(request) },
    data: { email, password: PASSWORD },
  })
  expect(login.ok()).toBeTruthy()

  // Keep using the app. Within a moment the session is gone, refresh fails, and we're signed out.
  await expect(async () => {
    await page.getByRole('link', { name: 'Notes' }).click()
    await page.getByRole('link', { name: 'My sessions' }).click()
    await expect(page.getByText('You were signed out. Please sign in again.')).toBeVisible({ timeout: 1_000 })
  }).toPass({ timeout: 20_000 })
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
})
