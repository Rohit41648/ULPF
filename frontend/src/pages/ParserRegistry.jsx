import React, { useEffect, useState } from 'react'
import { api } from '../services/api.js'

export default function ParserRegistry() {
  const [parsers, setParsers] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    api.listParsers().then(setParsers).catch((e) => setError(e.message))
  }, [])

  if (error) return <div className="panel p-4 text-sm text-danger">{error}</div>

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Parser registry</h1>
        <p className="text-sm text-mist mt-1 max-w-2xl">
          Every parser ULPF can run — five ship as deterministic, built-in parsers;
          others are generated on the fly by the unknown-source onboarding flow.
        </p>
      </div>

      <div className="panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-mist border-b border-line">
              <th className="px-4 py-2 font-normal">Name</th>
              <th className="px-4 py-2 font-normal">Vendor</th>
              <th className="px-4 py-2 font-normal">Format</th>
              <th className="px-4 py-2 font-normal">Version</th>
              <th className="px-4 py-2 font-normal">Type</th>
              <th className="px-4 py-2 font-normal">Status</th>
              <th className="px-4 py-2 font-normal">Created</th>
              <th className="px-4 py-2 font-normal">Events processed</th>
            </tr>
          </thead>
          <tbody>
            {parsers.map((p) => (
              <tr key={p.id} className="border-b border-line last:border-0 hover:bg-panel2/60">
                <td className="px-4 py-2 mono">{p.name}</td>
                <td className="px-4 py-2">{p.vendor || '—'}</td>
                <td className="px-4 py-2 text-mist">{p.format || '—'}</td>
                <td className="px-4 py-2 mono text-mist">v{p.version}</td>
                <td className="px-4 py-2">
                  <span className={`chip ${p.source_type === 'ai_generated' ? 'chip-warning' : 'chip-neutral'}`}>
                    {p.source_type === 'ai_generated' ? 'AI-generated' : 'deterministic'}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <span className={`chip ${p.status === 'active' ? 'chip-success' : 'chip-neutral'}`}>{p.status}</span>
                </td>
                <td className="px-4 py-2 text-mist">{new Date(p.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-2">{p.events_processed}</td>
              </tr>
            ))}
            {parsers.length === 0 && (
              <tr><td colSpan={8} className="px-4 py-6 text-center text-mist text-sm">No parsers registered yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
