// Records the README's demo (M11): the same stolen password, used through a Tor exit, against
// two organisations side by side.
//   left:  the Tor detector in observe mode, i.e. ThreatLock without automatic response
//   right: the default policy
// It saves screenshots of both at each step plus a manifest; scripts/demo/make-gif.py turns them
// into docs/assets/stolen-session-demo.gif.
//
// Needs the local stack: API (:5080), Worker (with the live Tor list) and `npx vite` (:5173).
//   node demo/record-demo.mjs [outDir]          (from web/; default ../artifacts/demo)
import { mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { chromium } from '@playwright/test'

const API = process.env.DEMO_API ?? 'http://127.0.0.1:5080'
const SPA = process.env.DEMO_SPA ?? 'http://localhost:5173'
const SIM_KEY = process.env.DEMO_SIM_KEY ?? 'dev-only-simulator-key-change-me'
const OFFICE_IP = '49.207.48.1' // Bengaluru, for the owners' sign-up
const PASSWORD = 'correct horse battery staple'
const OUT = resolve(process.argv[2] ?? '../artifacts/demo')
const RUN = Date.now()
const VIEWPORT = { width: 640, height: 560 }

const NOTES = [
  ['Q4 board deck: talking points', 'Revenue up 18%, two new enterprise logos, hiring freeze lifted in January.'],
  ['Payroll vendor: account details', 'Vendor portal login is in the vault. Rotate the API key after every quarter close.'],
  ['Customer escalations this week', 'Northwind wants SSO by Friday. Contoso disputes the October invoice.'],
  ['Roadmap 2027 (draft)', 'Self-serve SSO, audit export, regional data residency.'],
]

async function api(path, { method = 'GET', token, body, ip } = {}) {
  const headers = { 'Content-Type': 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  if (ip) Object.assign(headers, { 'X-Simulator-Key': SIM_KEY, 'X-Simulated-Client-Ip': ip })
  const response = await fetch(API + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  if (!response.ok) throw new Error(`${method} ${path} → ${response.status}: ${await response.text()}`)
  return response.status === 204 ? undefined : response.json()
}

/** An org with an owner, some shared notes and a user called Ben, whose password is about to leak. */
async function org(kind, torObserve) {
  const slug = `demo-${kind}-${RUN}`
  const owner = await api('/api/auth/register-org', {
    method: 'POST',
    ip: OFFICE_IP,
    body: { orgName: 'Acme Corp', orgSlug: slug, displayName: 'Asha (owner)', email: `asha-${slug}@acme.test`, password: PASSWORD },
  })
  for (const [title, body] of NOTES) await api('/api/notes', { method: 'POST', token: owner.accessToken, body: { title, body, shared: true } })
  const ben = `ben-${slug}@acme.test`
  await api('/api/admin/users', { method: 'POST', token: owner.accessToken, body: { email: ben, displayName: 'Ben', password: PASSWORD } })
  if (torObserve) {
    const current = await api('/api/admin/policy', { token: owner.accessToken })
    current.policy.detectors.tor.mode = 'observe'
    await api('/api/admin/policy', { method: 'PUT', token: owner.accessToken, body: { expectedVersion: current.version, policy: current.policy } })
  }
  return { owner: `asha-${slug}@acme.test`, ownerToken: owner.accessToken, ben }
}

async function torExit() {
  const list = await (await fetch('https://check.torproject.org/torbulkexitlist')).text()
  return list.split('\n').map((l) => l.trim()).find((l) => l && !l.startsWith('#'))
}

const frames = []
let n = 0
/** Screenshot both panels now; `ms` is how long the frame stays on screen in the GIF. */
async function snap(left, right, caption, ms = 900) {
  n += 1
  const id = String(n).padStart(3, '0')
  await Promise.all([left.screenshot({ path: join(OUT, `${id}-l.png`) }), right.screenshot({ path: join(OUT, `${id}-r.png`) })])
  frames.push({ left: `${id}-l.png`, right: `${id}-r.png`, caption, ms })
}

async function signIn(page, email) {
  await page.goto(SPA)
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Password').fill(PASSWORD)
}

/** Does the attacker still have a working session? Tries one action and reports what happened. */
async function attempt(page, action) {
  try {
    if (await page.getByText('You were signed out').isVisible()) return 'signed out'
    await action()
    return 'ok'
  } catch {
    return 'failed'
  }
}

async function main() {
  await mkdir(OUT, { recursive: true })
  const [before, after, tor] = await Promise.all([org('observe', true), org('default', false), torExit()])
  console.log(`Tor exit ${tor}; waiting 11 s for the Worker's policy cache`)
  await new Promise((r) => setTimeout(r, 11_000))

  const browser = await chromium.launch()
  const attacker = { extraHTTPHeaders: { 'X-Simulator-Key': SIM_KEY, 'X-Simulated-Client-Ip': tor }, viewport: VIEWPORT }
  const [a, b] = await Promise.all([browser.newContext(attacker), browser.newContext(attacker)])
  const [left, right] = await Promise.all([a.newPage(), b.newPage()])

  await Promise.all([signIn(left, before.ben), signIn(right, after.ben)])
  await snap(left, right, `The attacker has Ben's password and connects through a Tor exit node (${tor})`, 2200)

  await Promise.all([left.getByRole('button', { name: 'Sign in' }).click(), right.getByRole('button', { name: 'Sign in' }).click()])
  const signedInAt = Date.now()
  await Promise.all([left.getByText('Q4 board deck').waitFor(), right.getByText('Q4 board deck').waitFor().catch(() => {})])
  await snap(left, right, 'Signed in. Both see the company notes', 1600)

  // The attacker starts reading. On the right, the Worker has already revoked the session: the
  // first API call after sign-in gets a 401, refresh fails, and the SPA signs out.
  const steps = [
    ['Payroll vendor', 'Opens "Payroll vendor: account details"'],
    ['Customer escalations', 'Opens "Customer escalations this week"'],
    ['Export all', 'Clicks "Export all" to take everything'],
    ['Roadmap 2027', 'Keeps reading'],
  ]
  let revokedSeen = null
  for (const [target, what] of steps) {
    const act = (page) => () =>
      target === 'Export all'
        ? page.getByRole('button', { name: 'Export all' }).click({ timeout: 1500 })
        : page.getByRole('button', { name: new RegExp(target) }).click({ timeout: 1500 })
    await Promise.all([attempt(left, act(left)), attempt(right, act(right))])
    await left.waitForTimeout(400)
    if (!revokedSeen && (await right.getByText('You were signed out').isVisible())) revokedSeen = Date.now()
    const elapsed = ((Date.now() - signedInAt) / 1000).toFixed(1)
    await snap(left, right, `${what}  ·  ${elapsed} s after sign-in`, 1500)
  }

  // Server-side timings for the right-hand org, from the admin API.
  const [anomaly] = await api(`/api/admin/anomalies?detector=tor`, { token: after.ownerToken })
  const detail = await api(`/api/admin/anomalies/${anomaly.id}`, { token: after.ownerToken })
  const benLogin = new Date(anomaly.evidence.occurredAt).getTime()
  const revokedMs = new Date(detail.response.revokedAt).getTime() - benLogin
  console.log(`right: detected +${new Date(detail.detectedAt).getTime() - benLogin} ms, revoked +${revokedMs} ms`)

  // The admins' side.
  const adminOptions = { viewport: VIEWPORT }
  const [c, d] = await Promise.all([browser.newContext(adminOptions), browser.newContext(adminOptions)])
  const [adminLeft, adminRight] = await Promise.all([c.newPage(), d.newPage()])
  for (const [page, email] of [[adminLeft, before.owner], [adminRight, after.owner]]) {
    await signIn(page, email)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await page.getByRole('link', { name: 'Anomalies' }).waitFor()
  }
  await snap(adminLeft, adminRight, 'Meanwhile, the owner of each org signs in', 1400)

  for (const page of [adminLeft, adminRight]) {
    await page.getByRole('link', { name: 'Anomalies' }).click()
    await page.getByRole('cell', { name: 'Tor exit node (D1)' }).first().waitFor()
  }
  await snap(adminLeft, adminRight, 'Both detected the Tor login. Left: observed only. Right: responded', 2400)

  for (const page of [adminLeft, adminRight]) {
    await page.locator('tbody tr a').first().click()
    await page.getByText('Evidence').waitFor()
    // Bring the decision and the response timeline into view.
    await page.evaluate(() => document.querySelectorAll('h3')[0]?.scrollIntoView({ block: 'center' }))
  }
  await snap(adminLeft, adminRight, `Right: sessions revoked ${revokedMs} ms after the attacker signed in, admins notified`, 3200)

  for (const page of [adminLeft, adminRight]) {
    await page.getByRole('link', { name: /^Notifications/ }).click()
    await page.getByRole('heading', { name: 'Notifications' }).waitFor()
  }
  await snap(adminLeft, adminRight, 'Each admin is told once: "Tor exit node: Ben"', 2200)

  for (const page of [adminLeft, adminRight]) {
    await page.getByRole('link', { name: 'Audit log' }).click()
    await page.getByRole('button', { name: 'Verify chain' }).click()
    await page.getByRole('status').waitFor()
  }
  await snap(adminLeft, adminRight, 'Every step is in a hash-chained audit log that anyone can verify', 2800)

  await browser.close()
  await writeFile(
    join(OUT, 'manifest.json'),
    JSON.stringify({ leftTitle: 'Tor detector: observe only', rightTitle: 'ThreatLock default policy', revokedMs, tor, frames }, null, 2),
  )
  console.log(`${frames.length} frames in ${OUT}; the right-hand attacker saw "signed out" ${revokedSeen ? ((revokedSeen - signedInAt) / 1000).toFixed(1) + ' s' : 'never'} after sign-in`)
}

await main()
