import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { ApiError, request, send } from '../api/client'
import type { NoteRequest, NoteSummary, NoteView } from '../api/types'
import { useAuth } from '../auth/useAuth'

const empty: NoteRequest = { title: '', body: '', shared: false }

export function NotesPage({ token }: { token: string }) {
  const { expire } = useAuth()
  const [notes, setNotes] = useState<NoteSummary[]>([])
  const [selected, setSelected] = useState<NoteView | null>(null)
  const [draft, setDraft] = useState<NoteRequest>(empty)
  const [errors, setErrors] = useState<string[]>([])

  // Every API error goes through here: a 401 means the token is no longer accepted.
  const fail = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.status === 401) expire()
      else setErrors(error instanceof ApiError ? error.messages : [String(error)])
    },
    [expire],
  )

  const reload = useCallback(
    (signal?: AbortSignal) =>
      request<NoteSummary[]>('/api/notes', { token, signal })
        .then(setNotes)
        .catch((error: unknown) => signal?.aborted || fail(error)),
    [token, fail],
  )

  useEffect(() => {
    const controller = new AbortController()
    void reload(controller.signal)
    return () => controller.abort()
  }, [reload])

  async function open(id: string) {
    try {
      const note = await request<NoteView>(`/api/notes/${id}`, { token })
      setSelected(note)
      setDraft({ title: note.title, body: note.body, shared: note.shared })
      setErrors([])
    } catch (error) {
      fail(error)
    }
  }

  function startNew() {
    setSelected(null)
    setDraft(empty)
    setErrors([])
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    try {
      const saved = selected
        ? await request<NoteView>(`/api/notes/${selected.id}`, { method: 'PUT', body: draft, token })
        : await request<NoteView>('/api/notes', { method: 'POST', body: draft, token })
      setSelected(saved)
      setErrors([])
      await reload()
    } catch (error) {
      fail(error)
    }
  }

  async function remove() {
    if (!selected) return
    try {
      await send(`/api/notes/${selected.id}`, { method: 'DELETE', token })
      startNew()
      await reload()
    } catch (error) {
      fail(error)
    }
  }

  async function exportAll() {
    try {
      // The export is an authenticated download, so a plain <a href> can't send the token.
      // Fetch it, then hand the browser a temporary object URL to save.
      const response = await send('/api/notes/export', { token })
      const name = /filename="?([^";]+)"?/.exec(response.headers.get('Content-Disposition') ?? '')?.[1] ?? 'notes.json'
      const url = URL.createObjectURL(await response.blob())
      const link = Object.assign(document.createElement('a'), { href: url, download: name })
      link.click()
      URL.revokeObjectURL(url)
    } catch (error) {
      fail(error)
    }
  }

  const readOnly = selected !== null && !selected.isOwner

  return (
    <div className="notes">
      <aside>
        <div className="row">
          <button type="button" onClick={startNew}>
            New note
          </button>
          <button type="button" onClick={exportAll}>
            Export all
          </button>
        </div>
        {notes.length === 0 ? (
          <p>No notes yet.</p>
        ) : (
          <ul className="note-list">
            {notes.map((note) => (
              <li key={note.id}>
                <button type="button" className="link" onClick={() => open(note.id)} aria-current={selected?.id === note.id}>
                  {note.title}
                </button>{' '}
                <small>
                  {note.shared ? 'shared' : 'private'}
                  {!note.isOwner && ` · by ${note.ownerName}`}
                </small>
              </li>
            ))}
          </ul>
        )}
      </aside>

      <form onSubmit={save} className="stack">
        <h2>{selected ? (readOnly ? `${selected.title} (read-only)` : 'Edit note') : 'New note'}</h2>
        <label>
          Title
          <input value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} required maxLength={200} readOnly={readOnly} />
        </label>
        <label>
          Body
          <textarea value={draft.body} onChange={(e) => setDraft({ ...draft, body: e.target.value })} rows={10} maxLength={20000} readOnly={readOnly} />
        </label>
        <label className="row">
          <input type="checkbox" checked={draft.shared} onChange={(e) => setDraft({ ...draft, shared: e.target.checked })} disabled={readOnly} />
          Share with my organisation (read-only for others)
        </label>
        {errors.length > 0 && (
          <ul role="alert" className="errors">
            {errors.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        )}
        {!readOnly && (
          <div className="row">
            <button type="submit">Save</button>
            {selected && (
              <button type="button" onClick={remove}>
                Delete
              </button>
            )}
          </div>
        )}
      </form>
    </div>
  )
}
