import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api.js'
import StatusChip from '../components/StatusChip.jsx'

export default function EventsPage() {
  const [events, setEvents] = useState([])
  const [severity, setSeverity] = useState('')
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    api
      .listEvents(severity ? { severity, limit: 100 } : { limit: 100 })
      .then((data) => !cancelled && setEvents(data))
      .catch((e) => !cancelled && setError(e.message))
    return () => { cancelled = true }
  }, [severity])

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Events</h1>
          <p className="text-sm text-mist mt-1">Every normalized event, across every onboarded source.</p>
        </div>
        <select className="input w-40" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      <div className="panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-mist border-b border-line">
              <th className="px-4 py-2 font-normal">Time</th>
              <th className="px-4 py-2 font-normal">Vendor</th>
              <th className="px-4 py-2 font-normal">Format</th>
              <th className="px-4 py-2 font-normal">Event type</th>
              <th className="px-4 py-2 font-normal">Source IP</th>
              <th className="px-4 py-2 font-normal">Severity</th>
              <th className="px-4 py-2 font-normal">Confidence</th>
              <th className="px-4 py-2 font-normal">Status</th>
              <th className="px-4 py-2 font-normal"></th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-b border-line last:border-0 hover:bg-panel2/60">
                <td className="px-4 py-2 mono text-mist">{new Date(e.created_at).toLocaleString()}</td>
                <td className="px-4 py-2">{e.vendor || '—'}</td>
                <td className="px-4 py-2 text-mist">{e.format || '—'}</td>
                <td className="px-4 py-2">{e.event_type || '—'}</td>
                <td className="px-4 py-2 mono">{e.source_ip || '—'}</td>
                <td className="px-4 py-2"><StatusChip value={e.severity} /></td>
                <td className="px-4 py-2">{e.confidence != null ? `${Math.round(e.confidence * 100)}%` : '—'}</td>
                <td className="px-4 py-2"><StatusChip value={e.processing_status} /></td>
                <td className="px-4 py-2">
                  <Link to={`/traceability?event=${e.id}`} className="text-xs text-wire hover:underline">
                    Trace
                  </Link>
                </td>
              </tr>
            ))}
            {events.length === 0 && !error && (
              <tr>
                <td colSpan={9} className="px-4 py-6 text-center text-mist text-sm">
                  No events match this filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
