import React from 'react'

export default function MetricCard({ label, value, sub, accent }) {
  return (
    <div className="panel px-4 py-4">
      <div className="text-xs text-mist">{label}</div>
      <div className={`text-2xl font-semibold mt-1.5 ${accent || 'text-slate-100'}`}>{value}</div>
      {sub && <div className="text-xs text-mist mt-1">{sub}</div>}
    </div>
  )
}
