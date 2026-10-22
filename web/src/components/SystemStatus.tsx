import { useEffect, useState } from 'react'
import { getInfo, getReadiness, type AppInfo, type Readiness } from '../api/system'

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; info: AppInfo; readiness: Readiness }

/** Shows which build is running and whether its dependencies are reachable. */
export function SystemStatus() {
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    // Abort the requests if the component unmounts (or StrictMode re-runs the effect in dev).
    const controller = new AbortController()
    Promise.all([getInfo(controller.signal), getReadiness(controller.signal)])
      .then(([info, readiness]) => setState({ kind: 'ready', info, readiness }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return
        setState({ kind: 'error', message: error instanceof Error ? error.message : String(error) })
      })
    return () => controller.abort()
  }, [])

  if (state.kind === 'loading') return <p>Checking the API…</p>
  if (state.kind === 'error') return <p role="alert">API unreachable: {state.message}</p>

  const { info, readiness } = state
  return (
    <section aria-label="System status">
      <p>
        {info.name} <code>{info.version}</code> ({info.environment})
      </p>
      <p>
        Overall: <strong>{readiness.status}</strong>
      </p>
      <ul>
        {Object.entries(readiness.checks).map(([name, status]) => (
          <li key={name}>
            {name}: {status}
          </li>
        ))}
      </ul>
    </section>
  )
}
