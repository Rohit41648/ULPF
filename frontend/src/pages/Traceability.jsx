import React, { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../services/api.js'

export default function Traceability() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [eventId, setEventId] = useState(searchParams.get('event') || '')
  const [recentEvents, setRecentEvents] = useState([])
  const [trace, setTrace] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  // Blockchain verification state
  const [blockchainVerif, setBlockchainVerif] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [copied, setCopied] = useState(false)

  async function load(id) {
    if (!id.trim()) return
    setBusy(true)
    setError(null)
    setBlockchainVerif(null)
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

  // Load recent events for quick-picker dropdown
  useEffect(() => {
    api
      .listEvents({ limit: 20 })
      .then((data) => setRecentEvents(data))
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (eventId) load(eventId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function verifyOnBlockchain() {
    if (!eventId.trim()) return
    setVerifying(true)
    try {
      const res = await api.blockchainVerifyEvent(eventId.trim())
      setBlockchainVerif(res)
    } catch (e) {
      setBlockchainVerif({ verified: false, message: e.message })
    } finally {
      setVerifying(false)
    }
  }

  function copyTrace() {
    if (!trace) return
    navigator.clipboard.writeText(JSON.stringify(trace, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function downloadTrace() {
    if (!trace) return
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(trace, null, 2))
    const link = document.createElement('a')
    link.setAttribute('href', dataStr)
    link.setAttribute('download', `forensic_trace_${trace.event.id}.json`)
    link.click()
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Traceability</h1>
          <p className="text-sm text-mist mt-1 max-w-2xl">
            Every normalized event links back to the exact raw log it came from, and the
            exact parser version that produced it — the forensic backbone of ULPF.
          </p>
        </div>

        {trace && (
          <div className="flex items-center gap-2">
            <button
              onClick={copyTrace}
              className="text-xs px-3 py-1.5 rounded-md bg-panel2 border border-line text-slate-200 hover:border-wire hover:text-wire transition-colors"
            >
              {copied ? '✓ Copied' : 'Copy Trace JSON'}
            </button>
            <button
              onClick={downloadTrace}
              className="text-xs px-3 py-1.5 rounded-md bg-panel2 border border-line text-slate-200 hover:border-wire hover:text-wire transition-colors"
            >
              Download Audit Package
            </button>
          </div>
        )}
      </div>

      {/* Input panel & Quick-picker */}
      <div className="panel p-4 space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <input
            className="input flex-1 mono text-sm"
            placeholder="Paste an event ID…"
            value={eventId}
            onChange={(e) => setEventId(e.target.value)}
          />
          <button
            className="btn-primary"
            onClick={() => load(eventId)}
            disabled={busy || !eventId.trim()}
          >
            {busy ? 'Loading…' : 'Look up'}
          </button>
        </div>

        {/* Quick select dropdown */}
        {recentEvents.length > 0 && (
          <div className="flex items-center gap-2 text-xs text-mist pt-1">
            <span>Or pick a recent event:</span>
            <select
              className="input !py-1 text-xs bg-panel border-line text-slate-200 flex-1 max-w-md truncate"
              value={eventId}
              onChange={(e) => {
                const id = e.target.value
                setEventId(id)
                if (id) load(id)
              }}
            >
              <option value="">Select from recent events…</option>
              {recentEvents.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.vendor || 'Unknown'} — {e.event_type || 'Event'} ({new Date(e.created_at).toLocaleTimeString()}) - {e.id.slice(0, 8)}…
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      {trace && (
        <>
          {/* Forensic Pipeline Breadcrumb */}
          <div className="panel p-3.5 flex items-center justify-between gap-3 text-xs text-mist overflow-x-auto">
            <div className="flex items-center gap-2.5">
              <span className="mono text-slate-200 font-medium">raw_log:{trace.raw_log.id.slice(0, 10)}…</span>
              <span className="text-mist">→</span>
              <span className="mono text-slate-200 font-medium">
                {trace.parser?.name || 'unknown parser'} v{trace.parser?.version || '1.0.0'}
              </span>
              <span className="text-mist">→</span>
              <span className="mono text-emerald-400 font-medium">
                confidence {Math.round((trace.event.confidence || 0) * 100)}%
              </span>
              <span className="text-mist">→</span>
              <span className="mono text-slate-200 font-medium">event:{trace.event.id.slice(0, 10)}…</span>
            </div>

            <button
              onClick={verifyOnBlockchain}
              disabled={verifying}
              className="px-2.5 py-1 rounded bg-wire/15 border border-wire/30 text-wire hover:bg-wire/25 transition-colors text-xs font-medium whitespace-nowrap"
            >
              {verifying ? 'Verifying Ledger…' : '⛓️ Verify on Blockchain'}
            </button>
          </div>

          {/* Blockchain Verification Card (if queried) */}
          {blockchainVerif && (
            <div
              className={`panel p-4 border transition-all ${
                (blockchainVerif.verified ?? blockchainVerif.valid)
                  ? 'border-emerald-500/40 bg-emerald-500/5'
                  : 'border-amber-500/40 bg-amber-500/5'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-base">{(blockchainVerif.verified ?? blockchainVerif.valid) ? '🛡️' : '⚠️'}</span>
                  <span className="text-sm font-semibold text-slate-100">
                    {(blockchainVerif.verified ?? blockchainVerif.valid)
                      ? 'Cryptographic Ledger Verification Passed'
                      : 'Blockchain Ledger Status'}
                  </span>
                </div>
                <Link to="/blockchain" className="text-xs text-wire hover:underline">
                  Open Ledger Explorer →
                </Link>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs pt-1">
                <div>
                  <div className="text-mist">Block Index</div>
                  <div className="mono text-slate-200 mt-0.5">
                    {blockchainVerif.block_index != null ? `#${blockchainVerif.block_index}` : 'Pending / Not Batched'}
                  </div>
                </div>
                <div className="md:col-span-2">
                  <div className="text-mist">Block Hash (SHA-256)</div>
                  <div className="mono text-slate-300 mt-0.5 break-all">
                    {blockchainVerif.block_hash || '—'}
                  </div>
                </div>
              </div>

              {blockchainVerif.message && (
                <div className="text-xs text-mist mt-2 pt-2 border-t border-line/40">
                  {blockchainVerif.message}
                </div>
              )}
            </div>
          )}

          {/* 3-Column Forensic Evidence Panel */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Raw Log */}
            <div className="panel p-4">
              <div className="text-xs font-semibold text-slate-200 mb-2">1. Original Raw Ingest</div>
              <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto max-h-72 text-slate-300 whitespace-pre-wrap">
{trace.raw_log.raw_content}
              </pre>
              <div className="text-xs text-mist mt-3 space-y-1">
                <div>raw_log_id: <span className="mono text-slate-300">{trace.raw_log.id}</span></div>
                <div>ingested_at: <span className="mono text-slate-300">{new Date(trace.raw_log.ingested_at).toLocaleString()}</span></div>
                {trace.raw_log.integrity_status && (
                  <div>
                    integrity:{' '}
                    <span
                      className={`chip !py-0.5 !text-[10px] ${
                        trace.raw_log.integrity_status === 'VERIFIED'
                          ? 'chip-success'
                          : trace.raw_log.integrity_status === 'TAMPERED'
                          ? 'chip-danger'
                          : 'chip-neutral'
                      }`}
                    >
                      {trace.raw_log.integrity_status}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Parser Used */}
            <div className="panel p-4">
              <div className="text-xs font-semibold text-slate-200 mb-2">2. Parser Provenance</div>
              {trace.parser ? (
                <div className="space-y-2.5 text-sm">
                  <div className="mono text-slate-100 font-medium">{trace.parser.name}</div>
                  <div className="text-xs text-mist">Version v{trace.parser.version}</div>
                  <span
                    className={`chip ${
                      trace.parser.source_type === 'ai_generated' || trace.parser.source_type === 'ml_generated'
                        ? 'chip-warning'
                        : 'chip-neutral'
                    }`}
                  >
                    {trace.parser.source_type === 'ai_generated' || trace.parser.source_type === 'ml_generated'
                      ? 'Offline ML-Generated'
                      : 'Deterministic Regex'}
                  </span>
                  <div className="text-xs text-mist pt-2 space-y-1">
                    <div>
                      parser_id: <span className="mono text-slate-300">{trace.parser.id}</span>
                    </div>
                    <div>
                      processed_at: <span className="mono text-slate-300">{new Date(trace.event.created_at).toLocaleString()}</span>
                    </div>
                    <div>
                      parsing_confidence:{' '}
                      <span className="mono text-signal font-semibold">
                        {Math.round((trace.event.confidence || 0) * 100)}%
                      </span>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-mist">No parser recorded for this event.</div>
              )}
            </div>

            {/* Normalized Universal Event */}
            <div className="panel p-4">
              <div className="text-xs font-semibold text-slate-200 mb-2">3. Universal Schema Normalized Event</div>
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
