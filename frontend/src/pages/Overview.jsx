import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Bar, Doughnut } from 'react-chartjs-2'
import {
  Chart as ChartJS,
  ArcElement,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from 'chart.js'
import { api } from '../services/api.js'
import MetricCard from '../components/MetricCard.jsx'
import StatusChip from '../components/StatusChip.jsx'

ChartJS.register(ArcElement, BarElement, CategoryScale, LinearScale, Tooltip, Legend)

const CHART_COLORS = ['#4f8cff', '#5fd0b3', '#e8a33d', '#e5637a', '#9d7bea', '#3ac1d8']
const INTEGRITY_COLORS = { VERIFIED: '#22c55e', TAMPERED: '#ef4444', NO_HASH: '#6b7280' }

function chartOptions(extra = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#8b93a7', boxWidth: 10, font: { size: 11 } } } },
    scales: {
      x: { ticks: { color: '#8b93a7', font: { size: 11 } }, grid: { color: '#242b3a' } },
      y: { ticks: { color: '#8b93a7', font: { size: 11 } }, grid: { color: '#242b3a' }, beginAtZero: true },
    },
    ...extra,
  }
}

function doughnutOnlyOptions(extra = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#8b93a7', boxWidth: 10, font: { size: 11 } } } },
    ...extra,
  }
}

function IntegrityChip({ value }) {
  const styles = {
    VERIFIED: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    TAMPERED: 'bg-red-500/15 text-red-400 border-red-500/30 animate-pulse',
    NO_HASH:  'bg-gray-500/15 text-gray-400 border-gray-500/30',
  }
  const labels = { VERIFIED: '✓ Verified', TAMPERED: '⚠ Tampered', NO_HASH: '— No hash' }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${styles[value] || styles.NO_HASH}`}>
      {labels[value] || value || '—'}
    </span>
  )
}

export default function Overview() {
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [statsData, eventsData] = await Promise.all([api.stats(), api.listEvents({ limit: 8 })])
        if (!cancelled) {
          setStats(statsData)
          setEvents(eventsData)
        }
      } catch (e) {
        if (!cancelled) setError(e.message)
      }
    }
    load()
    const interval = setInterval(load, 5000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  if (error) {
    return (
      <div className="panel px-5 py-4 text-sm text-danger">
        Could not reach the backend at the configured API URL. Is it running? ({error})
      </div>
    )
  }
  if (!stats) return <div className="text-mist text-sm">Loading overview…</div>

  const formatLabels = Object.keys(stats.events_by_format)
  const vendorLabels = Object.keys(stats.events_by_vendor)
  const statusLabels = Object.keys(stats.processing_status_breakdown)

  const integrityTotal = stats.integrity_verified + stats.integrity_tampered + stats.integrity_no_hash
  const hasIntegrityData = integrityTotal > 0

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Overview</h1>
        <p className="text-sm text-mist mt-1 max-w-2xl">
          Intelligent preprocessing for heterogeneous security logs — every source is
          normalized into one universal schema before it reaches a SIEM, dashboard, or
          ML pipeline.
        </p>
      </div>

      {/* ─── Tamper Alert Banner ─── */}
      {stats.integrity_tampered > 0 && (
        <div className="relative overflow-hidden rounded-lg border border-red-500/40 bg-red-500/10 px-5 py-4">
          <div className="absolute inset-0 bg-gradient-to-r from-red-500/5 to-transparent" />
          <div className="relative flex items-start gap-3">
            <span className="text-2xl">🛡️</span>
            <div>
              <div className="text-sm font-semibold text-red-400">
                Data Integrity Alert — Tampering Detected
              </div>
              <p className="text-xs text-red-300/80 mt-1 max-w-xl leading-relaxed">
                <strong>{stats.integrity_tampered}</strong> uploaded {stats.integrity_tampered === 1 ? 'file has' : 'files have'} a
                SHA-256 hash mismatch. The data was modified between the browser's encryption step and
                the server's decryption step, indicating potential man-in-the-middle tampering or
                payload corruption.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <MetricCard label="Total logs" value={stats.total_logs} />
        <MetricCard label="Processed events" value={stats.processed_events} />
        <MetricCard label="Supported formats" value={stats.supported_formats} />
        <MetricCard
          label="Average confidence"
          value={`${Math.round(stats.average_confidence * 100)}%`}
          accent="text-signal"
        />
        <MetricCard
          label="Unknown sources pending"
          value={stats.unknown_sources_pending}
          accent={stats.unknown_sources_pending > 0 ? 'text-alert' : 'text-slate-100'}
        />
      </div>

      {/* ─── Integrity Verification Stats ─── */}
      {hasIntegrityData && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
          <div className="panel p-4 flex flex-col items-center justify-center">
            <div className="text-xs text-mist mb-1">Verified</div>
            <div className="text-2xl font-bold text-emerald-400">{stats.integrity_verified}</div>
            <div className="text-[10px] text-mist mt-1">hash matched</div>
          </div>
          <div className="panel p-4 flex flex-col items-center justify-center">
            <div className="text-xs text-mist mb-1">Tampered</div>
            <div className={`text-2xl font-bold ${stats.integrity_tampered > 0 ? 'text-red-400' : 'text-slate-400'}`}>
              {stats.integrity_tampered}
            </div>
            <div className="text-[10px] text-mist mt-1">hash mismatch</div>
          </div>
          <div className="panel p-4 flex flex-col items-center justify-center">
            <div className="text-xs text-mist mb-1">No Hash</div>
            <div className="text-2xl font-bold text-gray-400">{stats.integrity_no_hash}</div>
            <div className="text-[10px] text-mist mt-1">unencrypted upload</div>
          </div>
          <div className="panel p-4">
            <div className="text-sm font-medium text-slate-200 mb-3">Integrity breakdown</div>
            <div className="h-36 flex items-center justify-center">
              <Doughnut
                data={{
                  labels: ['Verified', 'Tampered', 'No Hash'],
                  datasets: [{
                    data: [stats.integrity_verified, stats.integrity_tampered, stats.integrity_no_hash],
                    backgroundColor: [INTEGRITY_COLORS.VERIFIED, INTEGRITY_COLORS.TAMPERED, INTEGRITY_COLORS.NO_HASH],
                  }],
                }}
                options={doughnutOnlyOptions()}
              />
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="panel p-4">
          <div className="text-sm font-medium text-slate-200 mb-3">Events by format</div>
          <div className="h-52">
            <Bar
              data={{
                labels: formatLabels,
                datasets: [{ data: formatLabels.map((f) => stats.events_by_format[f]), backgroundColor: CHART_COLORS }],
              }}
              options={chartOptions({ plugins: { legend: { display: false } } })}
            />
          </div>
        </div>
        <div className="panel p-4">
          <div className="text-sm font-medium text-slate-200 mb-3">Events by vendor</div>
          <div className="h-52">
            <Bar
              data={{
                labels: vendorLabels,
                datasets: [{ data: vendorLabels.map((v) => stats.events_by_vendor[v]), backgroundColor: CHART_COLORS }],
              }}
              options={chartOptions({ plugins: { legend: { display: false } } })}
            />
          </div>
        </div>
        <div className="panel p-4">
          <div className="text-sm font-medium text-slate-200 mb-3">Processing status</div>
          <div className="h-52 flex items-center justify-center">
            <Doughnut
              data={{
                labels: statusLabels,
                datasets: [{ data: statusLabels.map((s) => stats.processing_status_breakdown[s]), backgroundColor: CHART_COLORS }],
              }}
              options={doughnutOnlyOptions()}
            />
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="flex items-center justify-between px-4 py-3 border-b border-line">
          <div className="text-sm font-medium text-slate-200">Recent events</div>
          <Link to="/events" className="text-xs text-wire hover:underline">
            View all
          </Link>
        </div>
        <table className="w-full text-sm" style={{ tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: '10%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '15%' }} />
            <col style={{ width: '30%' }} />
            <col style={{ width: '12%' }} />
            <col style={{ width: '13%' }} />
          </colgroup>
          <thead>
            <tr className="text-left text-xs text-mist border-b border-line">
              <th className="px-4 py-2 font-normal">Time</th>
              <th className="px-4 py-2 font-normal">Vendor</th>
              <th className="px-4 py-2 font-normal">Format</th>
              <th className="px-4 py-2 font-normal">Event type</th>
              <th className="px-4 py-2 font-normal">Source IP</th>
              <th className="px-4 py-2 font-normal">Confidence</th>
              <th className="px-4 py-2 font-normal">Status</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-b border-line last:border-0 hover:bg-panel2/60">
                <td className="px-4 py-2 mono text-mist whitespace-nowrap">{new Date(e.created_at).toLocaleTimeString()}</td>
                <td className="px-4 py-2 whitespace-nowrap">{e.vendor || '—'}</td>
                <td className="px-4 py-2 text-mist whitespace-nowrap">{e.format || '—'}</td>
                <td className="px-4 py-2 whitespace-nowrap">{e.event_type || '—'}</td>
                <td className="px-4 py-2 mono overflow-hidden text-ellipsis whitespace-nowrap" title={e.source_ip || ''}>{e.source_ip || '—'}</td>
                <td className="px-4 py-2 whitespace-nowrap">{e.confidence != null ? `${Math.round(e.confidence * 100)}%` : '—'}</td>
                <td className="px-4 py-2 whitespace-nowrap">
                  <StatusChip value={e.processing_status} />
                </td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-6 text-center text-mist text-sm">
                  No events yet — process a log to see it here.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

