import React, { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api } from '../services/api.js'

export default function Traceability() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [eventId, setEventId] = useState(searchParams.get('event') || '')
  const [trace, setTrace] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function load(id) {
    if (!id.trim()) return
    setBusy(true)
    setError(null)
    try {
      const res = await api.getEventTrace(id.trim())
      setTrace(res)
      setSearchParams({ event: id.trim() })
    } catch (e) {
      setError(e.message)
      setTrace(null)
    } finally {
      setBusy(false)
    }
  }

  useEffect(() => {
    if (eventId) load(eventId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Traceability</h1>
        <p className="text-sm text-mist mt-1 max-w-2xl">
          Every normalized event links back to the exact raw log it came from, and the
          exact parser version that produced it — the forensic backbone of ULPF.
        </p>
      </div>

      <div className="panel p-4 flex items-center gap-3">
        <input
          className="input flex-1 mono"
          placeholder="Paste an event id…"
          value={eventId}
          onChange={(e) => setEventId(e.target.value)}
        />
        <button className="btn-primary" onClick={() => load(eventId)} disabled={busy || !eventId.trim()}>
          {busy ? 'Loading…' : 'Look up'}
        </button>
      </div>

      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      {trace && (
        <>
          <div className="panel p-3 flex items-center gap-3 text-xs text-mist overflow-x-auto">
            <span className="mono text-slate-200">raw_log:{trace.raw_log.id.slice(0, 10)}…</span>
            <span>→</span>
            <span className="mono text-slate-200">
              {trace.parser?.name || 'unknown parser'} v{trace.parser?.version}
            </span>
            <span>→</span>
            <span className="mono text-slate-200">confidence {Math.round((trace.event.confidence || 0) * 100)}%</span>
            <span>→</span>
            <span className="mono text-slate-200">event:{trace.event.id.slice(0, 10)}…</span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="panel p-4">
              <div className="text-xs text-mist mb-2">Original raw log</div>
              <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto max-h-72 text-slate-300 whitespace-pre-wrap">
{trace.raw_log.raw_content}
              </pre>
              <div className="text-xs text-mist mt-3 space-y-1">
                <div>raw_log_id: <span className="mono text-slate-300">{trace.raw_log.id}</span></div>
                <div>ingested_at: <span className="mono text-slate-300">{new Date(trace.raw_log.ingested_at).toLocaleString()}</span></div>
              </div>
            </div>

            <div className="panel p-4">
              <div className="text-xs text-mist mb-2">Parser used</div>
              {trace.parser ? (
                <div className="space-y-2 text-sm">
                  <div className="mono text-slate-100">{trace.parser.name}</div>
                  <div className="text-xs text-mist">version v{trace.parser.version}</div>
                  <span className={`chip ${trace.parser.source_type === 'ai_generated' ? 'chip-warning' : 'chip-neutral'}`}>
                    {trace.parser.source_type === 'ai_generated' ? 'AI-generated' : 'deterministic'}
                  </span>
                  <div className="text-xs text-mist pt-2">
                    parser_id: <span className="mono text-slate-300">{trace.parser.id}</span>
                  </div>
                  <div className="text-xs text-mist">
                    processing_timestamp: <span className="mono text-slate-300">{new Date(trace.event.created_at).toLocaleString()}</span>
                  </div>
                  <div className="text-xs text-mist">
                    confidence: <span className="mono text-signal">{Math.round((trace.event.confidence || 0) * 100)}%</span>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-mist">No parser recorded for this event.</div>
              )}
            </div>

            <div className="panel p-4">
              <div className="text-xs text-mist mb-2">Normalized universal event</div>
              <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto max-h-72 text-slate-300">
{JSON.stringify(trace.event.event_data, null, 2)}
              </pre>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
