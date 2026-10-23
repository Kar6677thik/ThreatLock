// A random id for this browser, created once and kept in localStorage (SPEC §6.8). The server
// uses it as a *signal* ("first login from a new device") for detectors, never as proof of
// identity: anyone can copy or invent one.

const KEY = 'threatlock.deviceId'

export function getDeviceId(): string {
  let id = localStorage.getItem(KEY)
  if (!id) {
    id = crypto.randomUUID()
    localStorage.setItem(KEY, id)
  }
  return id
}
