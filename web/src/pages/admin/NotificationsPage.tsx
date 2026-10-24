import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import type { Inbox, NotificationView } from '../../api/types'
import { useAuth } from '../../auth/useAuth'

/**
 * The admin's inbox (SPEC §10.4). Titles never contain IPs or note content; the details are
 * behind the anomaly link. Repeats about one user within an hour arrive as one entry with a count.
 */
export function NotificationsPage({ onChange }: { onChange?: () => void }) {
  const { call } = useAuth()
  const [inbox, setInbox] = useState<Inbox | null>(null)
  const [version, setVersion] = useState(0)

  useEffect(() => {
    call<Inbox>('/api/admin/notifications').then(setInbox)
  }, [call, version])

  async function markRead(item: NotificationView) {
    await call(`/api/admin/notifications/${item.id}/read`, { method: 'POST' })
    setVersion((v) => v + 1)
    onChange?.()
  }

  async function markAllRead() {
    await call('/api/admin/notifications/read-all', { method: 'POST' })
    setVersion((v) => v + 1)
    onChange?.()
  }

  if (!inbox) return <p>Loading…</p>

  return (
    <section>
      <div className="row spread">
        <h2>Notifications</h2>
        {inbox.unread > 0 && (
          <button type="button" onClick={() => void markAllRead()}>
            Mark all as read
          </button>
        )}
      </div>
      {inbox.items.length === 0 ? (
        <p>Nothing yet. Anomalies that need your attention will appear here.</p>
      ) : (
        <ul className="inbox">
          {inbox.items.map((item) => (
            <li key={item.id} className={item.readAt ? 'read' : 'unread'}>
              <Link to={`/admin/anomalies/${item.lastAnomalyId}`}>{item.title}</Link>
              {item.count > 1 && <span className="badge" title="Anomalies about this user, grouped">×{item.count}</span>}{' '}
              <small>{new Date(item.updatedAt).toLocaleString()}</small>{' '}
              {!item.readAt && (
                <button type="button" className="link" onClick={() => void markRead(item)}>
                  Mark as read
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
