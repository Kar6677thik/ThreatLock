import { SystemStatus } from './components/SystemStatus'

// M1 shell. Login and notes arrive in M2, the admin screens from M5 (SPEC §14).
export default function App() {
  return (
    <main>
      <h1>ThreatLock</h1>
      <p>Detect a stolen session and kill it in seconds, not hours.</p>
      <SystemStatus />
    </main>
  )
}
