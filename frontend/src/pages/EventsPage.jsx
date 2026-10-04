import React, { useEffect, useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api.js'
import StatusChip from '../components/StatusChip.jsx'

const SEVERITY_OPTIONS = ['low', 'medium', 'high', 'unknown']

export default function EventsPage() {
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [editingEvent, setEditingEvent] = useState(null)
  const [deletingEvent, setDeletingEvent] = useState(null)
  const [inspectingEvent, setInspectingEvent] = useState(null)
  const [showBulkDeleteConfirm, setShowBulkDeleteConfirm] = useState(false)
  const [busy, setBusy] = useState(false)
  const [toast, setToast] = useState(null)

  // ── Filters & Search ──
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [vendorFilter, setVendorFilter] = useState('all')

  function showToast(msg, type = 'success') {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3500)
  }

  function loadEvents() {
    api
      .listEvents({ limit: 200 })
      .then((data) => {
        setEvents(data)
        setSelectedIds(new Set())
      })
      .catch((e) => setError(e.message))
  }

  useEffect(() => {
    loadEvents()
  }, [])

  // Unique vendors list for dropdown
  const uniqueVendors = useMemo(() => {
    const set = new Set()
    events.forEach((e) => {
      const v = e.vendor && e.vendor !== '—' ? e.vendor : 'Unknown'
      set.add(v)
    })
    return Array.from(set).sort((a, b) => {
      if (a === 'Unknown') return 1
      if (b === 'Unknown') return -1
      return a.localeCompare(b)
    })
  }, [events])

  // Filtered events
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      const s = (e.severity || 'unknown').toLowerCase()
      if (severityFilter !== 'all' && s !== severityFilter.toLowerCase()) {
        return false
      }
      const v = e.vendor && e.vendor !== '—' ? e.vendor : 'Unknown'
      if (vendorFilter !== 'all' && v.toLowerCase() !== vendorFilter.toLowerCase()) {
        return false
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const match =
          (e.event_type && e.event_type.toLowerCase().includes(q)) ||
          v.toLowerCase().includes(q) ||
          s.includes(q) ||
          (e.format && e.format.toLowerCase().includes(q)) ||
          (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
          (e.id && e.id.toLowerCase().includes(q))
        if (!match) return false
      }
      return true
    })
  }, [events, severityFilter, vendorFilter, searchQuery])

  // ─── Selection helpers ───
  const allSelected = filteredEvents.length > 0 && selectedIds.size === filteredEvents.length

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(filteredEvents.map((e) => e.id)))
    }
  }

  function toggleSelectOne(id) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // ─── Export CSV ───
  function exportCSV() {
    if (filteredEvents.length === 0) return
    const headers = ['id', 'created_at', 'vendor', 'format', 'event_type', 'source_ip', 'severity', 'confidence', 'processing_status']
    const rows = filteredEvents.map((e) => [
      `"${e.id}"`,
      `"${new Date(e.created_at).toISOString()}"`,
      `"${e.vendor && e.vendor !== '—' ? e.vendor : 'Unknown'}"`,
      `"${e.format || ''}"`,
      `"${e.event_type || ''}"`,
      `"${e.source_ip || ''}"`,
      `"${e.severity || 'unknown'}"`,
      e.confidence != null ? e.confidence : '',
      `"${e.processing_status || ''}"`,
    ])
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n')
    const encodedUri = encodeURI(csvContent)
    const link = document.createElement('a')
    link.setAttribute('href', encodedUri)
    link.setAttribute('download', `ulpf_events_${Date.now()}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    showToast(`Exported ${filteredEvents.length} events to CSV.`)
  }

  // ─── Export JSON ───
  function exportJSON() {
    if (filteredEvents.length === 0) return
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredEvents, null, 2))
    const link = document.createElement('a')
    link.setAttribute('href', dataStr)
    link.setAttribute('download', `ulpf_events_${Date.now()}.json`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    showToast(`Exported ${filteredEvents.length} events to JSON.`)
  }

  // ─── Edit Event ───
  async function handleSaveEdit(updatedData) {
    if (!editingEvent) return
    setBusy(true)
    try {
      const updated = await api.updateEvent(editingEvent.id, updatedData)
      setEvents((prev) => prev.map((e) => (e.id === editingEvent.id ? updated : e)))
      setEditingEvent(null)
      showToast('Event updated successfully.')
    } catch (e) {
      showToast(e.message, 'danger')
    } finally {
      setBusy(false)
    }
  }

  // ─── Single Delete ───
  async function handleConfirmDelete() {
    if (!deletingEvent) return
    setBusy(true)
    try {
      await api.deleteEvent(deletingEvent.id)
      setEvents((prev) => prev.filter((e) => e.id !== deletingEvent.id))
      setSelectedIds((prev) => {
        const next = new Set(prev)
        next.delete(deletingEvent.id)
        return next
      })
      setDeletingEvent(null)
      showToast('Event deleted successfully.')
    } catch (e) {
      showToast(e.message, 'danger')
    } finally {
      setBusy(false)
    }
  }

  // ─── Bulk Delete ───
  async function handleConfirmBulkDelete() {
    if (selectedIds.size === 0) return
    setBusy(true)
    try {
      const ids = Array.from(selectedIds)
      const res = await api.bulkDeleteEvents(ids)
      setEvents((prev) => prev.filter((e) => !selectedIds.has(e.id)))
      setSelectedIds(new Set())
      setShowBulkDeleteConfirm(false)
      showToast(`${res.deleted_count} event(s) deleted successfully.`)
    } catch (e) {
      showToast(e.message, 'danger')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-5">
      {/* Toast Notification */}
      {toast && (
        <div
          className={`fixed top-4 right-4 z-50 px-4 py-2.5 rounded-lg shadow-lg text-xs font-medium border transition-all ${
            toast.type === 'danger'
              ? 'bg-red-500/20 text-red-300 border-red-500/40'
              : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
          }`}
        >
          {toast.msg}
        </div>
      )}

      {/* Header & Bulk Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Events</h1>
          <p className="text-sm text-mist mt-1">
            Every normalized event, across every onboarded source ({events.length} total).
          </p>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap">
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2 bg-panel2 border border-line px-3 py-1 rounded-lg">
              <span className="text-xs text-slate-200 font-medium">
                <strong className="text-wire">{selectedIds.size}</strong> selected
              </span>
              <button
                onClick={() => setShowBulkDeleteConfirm(true)}
                className="text-xs px-2.5 py-1 rounded bg-red-600/80 hover:bg-red-600 text-white font-medium transition-colors"
              >
                Delete Selected
              </button>
              <button
                onClick={() => setSelectedIds(new Set())}
                className="text-xs text-mist hover:text-slate-200 transition-colors"
              >
                Clear
              </button>
            </div>
          )}

          <button
            onClick={exportCSV}
            disabled={filteredEvents.length === 0}
            className="text-xs px-3 py-1.5 rounded-md bg-panel2 border border-line text-slate-200 hover:border-wire hover:text-wire transition-colors disabled:opacity-50"
            title="Download CSV of current table"
          >
            Export CSV
          </button>
          <button
            onClick={exportJSON}
            disabled={filteredEvents.length === 0}
            className="text-xs px-3 py-1.5 rounded-md bg-panel2 border border-line text-slate-200 hover:border-wire hover:text-wire transition-colors disabled:opacity-50"
            title="Download JSON of current table"
          >
            Export JSON
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="panel p-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-1 min-w-[240px]">
          <span className="text-xs text-mist">🔍</span>
          <input
            type="text"
            className="input !py-1 text-xs flex-1"
            placeholder="Search by event type, vendor, IP, format, or ID…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="text-xs text-mist hover:text-slate-200"
            >
              ✕
            </button>
          )}
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-xs text-mist">
            <span>Severity:</span>
            <select
              className="input !py-1 text-xs bg-panel border-line text-slate-200"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
            >
              <option value="all">All Severities</option>
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-1.5 text-xs text-mist">
            <span>Vendor:</span>
            <select
              className="input !py-1 text-xs bg-panel border-line text-slate-200"
              value={vendorFilter}
              onChange={(e) => setVendorFilter(e.target.value)}
            >
              <option value="all">All Vendors</option>
              {uniqueVendors.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          </div>

          {(searchQuery || severityFilter !== 'all' || vendorFilter !== 'all') && (
            <button
              onClick={() => {
                setSearchQuery('')
                setSeverityFilter('all')
                setVendorFilter('all')
              }}
              className="text-xs text-wire hover:underline"
            >
              Reset filters
            </button>
          )}
        </div>
      </div>

      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      {/* Events Table */}
      <div className="panel overflow-x-auto">
        <table className="w-full text-sm" style={{ minWidth: 950 }}>
          <thead>
            <tr className="text-left text-xs text-mist border-b border-line">
              <th className="px-4 py-2.5 font-normal w-10">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={toggleSelectAll}
                  className="accent-wire rounded cursor-pointer"
                  title="Select all matching"
                />
              </th>
              <th className="px-4 py-2.5 font-normal whitespace-nowrap">Time</th>
              <th className="px-4 py-2.5 font-normal whitespace-nowrap">Vendor</th>
              <th className="px-4 py-2.5 font-normal whitespace-nowrap">Format</th>
              <th className="px-4 py-2.5 font-normal whitespace-nowrap">Event Type (Name)</th>
              <th className="px-4 py-2.5 font-normal whitespace-nowrap">Source IP</th>
              <th className="px-4 py-2.5 font-normal whitespace-nowrap">Severity</th>
              <th className="px-4 py-2.5 font-normal whitespace-nowrap">Confidence</th>
              <th className="px-4 py-2.5 font-normal whitespace-nowrap text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredEvents.map((e) => {
              const isSelected = selectedIds.has(e.id)
              return (
                <tr
                  key={e.id}
                  className={`border-b border-line last:border-0 hover:bg-panel2/60 transition-colors ${
                    isSelected ? 'bg-wire/5' : ''
                  }`}
                >
                  <td className="px-4 py-2.5">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleSelectOne(e.id)}
                      className="accent-wire rounded cursor-pointer"
                    />
                  </td>
                  <td className="px-4 py-2.5 mono text-mist whitespace-nowrap">
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">{e.vendor && e.vendor !== '—' ? e.vendor : 'Unknown'}</td>
                  <td className="px-4 py-2.5 text-mist whitespace-nowrap">{e.format || '—'}</td>
                  <td className="px-4 py-2.5 whitespace-nowrap">
                    <span className="mono text-slate-200 font-medium">{e.event_type || '—'}</span>
                  </td>
                  <td className="px-4 py-2.5 mono whitespace-nowrap" style={{ maxWidth: 160 }}>
                    <span className="block truncate">{e.source_ip || '—'}</span>
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">
                    <StatusChip value={e.severity} />
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap text-mist">
                    {e.confidence != null ? `${Math.round(e.confidence * 100)}%` : '—'}
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => setInspectingEvent(e)}
                        className="text-xs px-2 py-0.5 rounded bg-wire/10 text-wire hover:bg-wire/20 transition-colors"
                        title="View full event details"
                      >
                        Inspect
                      </button>
                      <Link
                        to={`/traceability?event=${e.id}`}
                        className="text-xs text-mist hover:text-slate-200 px-1 py-0.5"
                        title="View forensic trace"
                      >
                        Trace
                      </Link>
                      <button
                        onClick={() => setEditingEvent(e)}
                        className="text-xs px-2 py-0.5 rounded bg-panel2 border border-line text-slate-300 hover:text-slate-100 hover:border-wire transition-colors"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => setDeletingEvent(e)}
                        className="text-xs px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 transition-colors"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              )
            })}
            {filteredEvents.length === 0 && !error && (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-mist text-sm">
                  {events.length === 0
                    ? 'No events found.'
                    : 'No events match the selected filters or search query.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ─── Inspect Event Modal ─── */}
      {inspectingEvent && (
        <InspectEventModal
          event={inspectingEvent}
          onClose={() => setInspectingEvent(null)}
          onEdit={() => {
            const ev = inspectingEvent
            setInspectingEvent(null)
            setEditingEvent(ev)
          }}
        />
      )}

      {/* ─── Edit Event Modal ─── */}
      {editingEvent && (
        <EditEventModal
          event={editingEvent}
          busy={busy}
          onSave={handleSaveEdit}
          onClose={() => setEditingEvent(null)}
        />
      )}

      {/* ─── Single Delete Confirmation ─── */}
      {deletingEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="panel max-w-md w-full p-5 space-y-4 border border-line shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center text-red-400">
                ⚠
              </div>
              <h3 className="text-base font-semibold text-slate-100">Delete Event</h3>
            </div>
            <p className="text-sm text-mist leading-relaxed">
              Are you sure you want to permanently delete event{' '}
              <strong className="mono text-slate-200">{deletingEvent.id.slice(0, 12)}…</strong>?
              This action cannot be undone.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                className="btn-secondary !py-1.5 !px-3 text-xs"
                onClick={() => setDeletingEvent(null)}
                disabled={busy}
              >
                Cancel
              </button>
              <button
                type="button"
                className="px-3 py-1.5 rounded-md bg-red-600 hover:bg-red-500 text-white text-xs font-medium transition-colors"
                onClick={handleConfirmDelete}
                disabled={busy}
              >
                {busy ? 'Deleting…' : 'Delete Event'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Bulk Delete Confirmation ─── */}
      {showBulkDeleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="panel max-w-md w-full p-5 space-y-4 border border-line shadow-2xl">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center text-red-400">
                ⚠
              </div>
              <h3 className="text-base font-semibold text-slate-100">Bulk Delete Events</h3>
            </div>
            <p className="text-sm text-mist leading-relaxed">
              Are you sure you want to permanently delete <strong className="text-red-400">{selectedIds.size}</strong> selected events? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                className="btn-secondary !py-1.5 !px-3 text-xs"
                onClick={() => setShowBulkDeleteConfirm(false)}
                disabled={busy}
              >
                Cancel
              </button>
              <button
                type="button"
                className="px-3 py-1.5 rounded-md bg-red-600 hover:bg-red-500 text-white text-xs font-medium transition-colors"
                onClick={handleConfirmBulkDelete}
                disabled={busy}
              >
                {busy ? 'Deleting…' : `Delete ${selectedIds.size} Events`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function InspectEventModal({ event, onClose, onEdit }) {
  const [copied, setCopied] = useState(false)

  function copyJSON() {
    navigator.clipboard.writeText(JSON.stringify(event.event_data, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="panel max-w-2xl w-full p-6 space-y-4 border border-line shadow-2xl">
        <div className="flex items-center justify-between border-b border-line pb-3">
          <div className="flex items-center gap-2.5">
            <h3 className="text-base font-semibold text-slate-100">{event.event_type || 'Event Details'}</h3>
            <StatusChip value={event.severity} />
            <span className="chip chip-neutral">{event.vendor && event.vendor !== '—' ? event.vendor : 'Unknown'}</span>
          </div>
          <button onClick={onClose} className="text-mist hover:text-slate-100 text-lg">
            ✕
          </button>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div>
            <div className="text-mist">Format</div>
            <div className="text-slate-200 mt-0.5 mono">{event.format || '—'}</div>
          </div>
          <div>
            <div className="text-mist">Source IP</div>
            <div className="text-slate-200 mt-0.5 mono">{event.source_ip || '—'}</div>
          </div>
          <div>
            <div className="text-mist">Confidence</div>
            <div className="text-emerald-400 mt-0.5 font-semibold">
              {event.confidence != null ? `${Math.round(event.confidence * 100)}%` : '—'}
            </div>
          </div>
          <div>
            <div className="text-mist">Status</div>
            <div className="text-slate-200 mt-0.5">{event.processing_status}</div>
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-medium text-slate-300">Universal Schema JSON</span>
            <button
              onClick={copyJSON}
              className="text-xs px-2 py-0.5 rounded bg-panel2 border border-line text-mist hover:text-slate-200 transition-colors"
            >
              {copied ? '✓ Copied' : 'Copy JSON'}
            </button>
          </div>
          <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto max-h-64 text-slate-300">
            {JSON.stringify(event.event_data, null, 2)}
          </pre>
        </div>

        <div className="flex items-center justify-between pt-2 border-t border-line text-xs">
          <div className="flex items-center gap-3">
            <Link
              to={`/traceability?event=${event.id}`}
              className="text-wire hover:underline flex items-center gap-1"
            >
              Forensic Trace →
            </Link>
            <Link
              to="/blockchain"
              className="text-mist hover:text-slate-200 flex items-center gap-1"
            >
              Blockchain Ledger →
            </Link>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="btn-secondary !py-1 !px-3 text-xs"
              onClick={onEdit}
            >
              Edit Event
            </button>
            <button
              type="button"
              className="btn-primary !py-1 !px-3 text-xs"
              onClick={onClose}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function EditEventModal({ event, busy, onSave, onClose }) {
  const [eventType, setEventType] = useState(event.event_type || '')
  const [severity, setSeverity] = useState(event.severity || 'low')

  function handleSubmit(e) {
    e.preventDefault()
    onSave({
      event_type: eventType.trim(),
      severity: severity.trim().toLowerCase(),
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="panel max-w-md w-full p-5 space-y-4 border border-line shadow-2xl">
        <div className="flex items-center justify-between border-b border-line pb-3">
          <div>
            <h3 className="text-base font-semibold text-slate-100">Edit Event</h3>
            <p className="text-xs text-mist mt-0.5">Modify event name/type and severity level.</p>
          </div>
          <button onClick={onClose} className="text-mist hover:text-slate-100 text-lg">
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-mist mb-1">Event Type / Name</label>
            <input
              type="text"
              className="input w-full mono text-sm"
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              placeholder="e.g. network_connection, auth_event"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-mist mb-1">Severity</label>
            <select
              className="input w-full text-sm"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {SEVERITY_OPTIONS.map((sev) => (
                <option key={sev} value={sev}>
                  {sev.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          <div className="text-xs text-mist/80 bg-ink/50 p-2.5 rounded border border-line">
            Event ID: <span className="mono text-slate-300">{event.id}</span>
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-line">
            <button
              type="button"
              className="btn-secondary !py-1.5 !px-3 text-xs"
              onClick={onClose}
              disabled={busy}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary !py-1.5 !px-4 text-xs font-medium"
              disabled={busy}
            >
              {busy ? 'Saving…' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
