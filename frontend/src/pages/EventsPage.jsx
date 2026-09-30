import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api.js'
import StatusChip from '../components/StatusChip.jsx'

export default function EventsPage() {
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    api
      .listEvents({ limit: 100 })
      .then((data) => !cancelled && setEvents(data))
      .catch((e) => !cancelled && setError(e.message))
    return () => { cancelled = true }
  }, [])

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Events</h1>
        <p className="text-sm text-mist mt-1">Every normalized event, across every onboarded source.</p>
      </div>

      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      <div className="panel overflow-x-auto">
        <table className="w-full text-sm" style={{ minWidth: 900 }}>
          <thead>
            <tr className="text-left text-xs text-mist border-b border-line">
              <th className="px-4 py-2 font-normal whitespace-nowrap">Time</th>
              <th className="px-4 py-2 font-normal whitespace-nowrap">Vendor</th>
              <th className="px-4 py-2 font-normal whitespace-nowrap">Format</th>
              <th className="px-4 py-2 font-normal whitespace-nowrap">Event type</th>
              <th className="px-4 py-2 font-normal whitespace-nowrap">Source IP</th>
              <th className="px-4 py-2 font-normal whitespace-nowrap">Severity</th>
              <th className="px-4 py-2 font-normal whitespace-nowrap">Confidence</th>
              <th className="px-4 py-2 font-normal whitespace-nowrap"></th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-b border-line last:border-0 hover:bg-panel2/60">
                <td className="px-4 py-2 mono text-mist whitespace-nowrap">{new Date(e.created_at).toLocaleString()}</td>
                <td className="px-4 py-2 whitespace-nowrap">{e.vendor || '—'}</td>
                <td className="px-4 py-2 text-mist whitespace-nowrap">{e.format || '—'}</td>
                <td className="px-4 py-2 whitespace-nowrap">{e.event_type || '—'}</td>
                <td className="px-4 py-2 mono whitespace-nowrap" style={{ maxWidth: 160 }}>
                  <span className="block truncate">{e.source_ip || '—'}</span>
                </td>
                <td className="px-4 py-2 whitespace-nowrap"><StatusChip value={e.severity} /></td>
                <td className="px-4 py-2 whitespace-nowrap">{e.confidence != null ? `${Math.round(e.confidence * 100)}%` : '—'}</td>
                <td className="px-4 py-2 whitespace-nowrap">
                  <Link to={`/traceability?event=${e.id}`} className="text-xs text-wire hover:underline">
                    Trace
                  </Link>
                </td>
              </tr>
            ))}
            {events.length === 0 && !error && (
              <tr>
                <td colSpan={9} className="px-4 py-6 text-center text-mist text-sm">
                  No events found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
