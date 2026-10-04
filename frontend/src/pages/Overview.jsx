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
const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#64748b',
  unknown: '#475569',
}

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

export default function Overview() {
  const [stats, setStats] = useState(null)
  const [health, setHealth] = useState(null)
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [statsData, healthData, eventsData] = await Promise.all([
          api.stats(),
          api.health().catch(() => null),
          api.listEvents({ limit: 8 }),
        ])
        if (!cancelled) {
          setStats(statsData)
          if (healthData) setHealth(healthData)
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

  const formatLabels = Object.keys(stats.events_by_format || {})
  const vendorLabels = Object.keys(stats.events_by_vendor || {})
  const severityLabels = Object.keys(stats.events_by_severity || {})
  const statusLabels = Object.keys(stats.processing_status_breakdown || {})

  const integrityTotal = (stats.integrity_verified || 0) + (stats.integrity_tampered || 0) + (stats.integrity_no_hash || 0)
  const hasIntegrityData = integrityTotal > 0

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Overview</h1>
          <p className="text-sm text-mist mt-1 max-w-2xl">
            Intelligent preprocessing for heterogeneous security logs — normalized into one
            universal schema with offline ML, cryptographic integrity, and blockchain auditing.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link
            to="/analyzer"
            className="text-xs px-3 py-1.5 rounded-md bg-wire/15 border border-wire/30 text-wire hover:bg-wire/25 transition-colors font-medium"
          >
            Analyze Log Line →
          </Link>
          <Link
            to="/blockchain"
            className="text-xs px-3 py-1.5 rounded-md bg-panel2 border border-line text-mist hover:text-slate-200 transition-colors"
          >
            Ledger Explorer
          </Link>
        </div>
      </div>

      {/* ─── System Engine Health Status Bar ─── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Card 1: Offline ML */}
        <div className="panel p-3.5 border border-line flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200">Offline ML Classifier</span>
            <span className="flex items-center gap-1.5 text-[11px] text-emerald-400 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              Active
            </span>
          </div>
          <div className="mt-2 text-xs text-mist">
            Random Forest (13 targets)
          </div>


        </div>

        {/* Card 2: Cryptographic System */}
        <div className="panel p-3.5 border border-line flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200">Zero-Knowledge Crypto</span>
            <span className="flex items-center gap-1.5 text-[11px] text-emerald-400 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              Armed
            </span>
          </div>
          <div className="mt-2 text-xs text-mist">
            AES-256-GCM + RSA-OAEP
          </div>
          <div className="mt-1 text-[10px] text-mist">
            Client-side envelope payload sealing
          </div>
        </div>

        {/* Card 3: Blockchain Audit Ledger */}
        <Link
          to="/blockchain"
          className={`panel p-3.5 border transition-all flex flex-col justify-between ${
            health?.blockchain?.chain_valid === false
              ? 'border-red-500/60 bg-red-500/10 hover:border-red-400 hover:bg-red-500/15'
              : 'border-line hover:border-wire/40'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200">Blockchain Ledger</span>
            <span
              className={`flex items-center gap-1.5 text-[11px] font-semibold ${
                health?.blockchain?.chain_valid !== false
                  ? 'text-emerald-400'
                  : 'text-red-400'
              }`}
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  health?.blockchain?.chain_valid !== false
                    ? 'bg-emerald-400'
                    : 'bg-red-400 animate-pulse'
                }`}
              />
              {health?.blockchain?.chain_valid !== false
                ? 'Valid'
                : `Compromised (${health?.blockchain?.tampered_count || 1})`}
            </span>
          </div>
          <div className="mt-2 text-xs text-mist">
            {health?.blockchain?.total_blocks ?? '—'} Merkle blocks chained
          </div>
          <div className="mt-1 text-[10px] flex items-center justify-between">
            <span className="text-mist">SHA-256 Immutable hash sequence</span>
            {health?.blockchain?.chain_valid === false && (
              <span className="text-red-400 font-semibold underline text-[10px]">Inspect Breach →</span>
            )}
          </div>
        </Link>

        {/* Card 4: Database Core */}
        <div className="panel p-3.5 border border-line flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-200">Database Engine</span>
            <span className="flex items-center gap-1.5 text-[11px] text-emerald-400 font-medium">
              <span className="w-2 h-2 rounded-full bg-emerald-400" />
              Online
            </span>
          </div>
          <div className="mt-2 text-xs text-mist">
            SQLite / Transactional ACID
          </div>
          <div className="mt-1 text-[10px] text-mist">
            Normalized universal schema storage
          </div>
        </div>
      </div>

      {/* ─── Blockchain Cryptographic Breach Alert Banner ─── */}
      {health?.blockchain?.chain_valid === false && (
        <div className="relative overflow-hidden rounded-lg border border-red-500/50 bg-red-500/15 px-5 py-4">
          <div className="absolute inset-0 bg-gradient-to-r from-red-500/10 to-transparent pointer-events-none" />
          <div className="relative flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div className="flex items-start gap-3">
              <span className="text-2xl">🚨</span>
              <div>
                <div className="text-sm font-semibold text-red-300">
                  Blockchain Cryptographic Breach Detected
                </div>
                <p className="text-xs text-red-200/90 mt-1 max-w-2xl leading-relaxed">
                  The SHA-256 Merkle hash chain has failed integrity verification. One or more recorded
                  forensic blocks ({health?.blockchain?.corrupted_blocks?.map((b) => `#${b}`).join(', ') || 'Block #1'}) have been altered directly in storage.
                </p>
              </div>
            </div>
            <Link
              to="/blockchain"
              className="btn-primary !bg-red-600 hover:!bg-red-500 text-white !py-1.5 !px-3 text-xs shrink-0 self-start sm:self-center font-medium shadow-lg"
            >
              Inspect Breach on Blockchain →
            </Link>
          </div>
        </div>
      )}

      {/* ─── Ingest Payload Tamper Alert Banner ─── */}
      {stats.integrity_tampered > 0 && health?.blockchain?.chain_valid !== false && (
        <div className="relative overflow-hidden rounded-lg border border-red-500/40 bg-red-500/10 px-5 py-4">
          <div className="absolute inset-0 bg-gradient-to-r from-red-500/5 to-transparent" />
          <div className="relative flex items-start gap-3">
            <span className="text-2xl">🛡️</span>
            <div>
              <div className="text-sm font-semibold text-red-400">
                Data Integrity Alert — Ingest Tampering Detected
              </div>
              <p className="text-xs text-red-300/80 mt-1 max-w-xl leading-relaxed">
                <strong>{stats.integrity_tampered}</strong> uploaded {stats.integrity_tampered === 1 ? 'file has' : 'files have'} a
                SHA-256 hash mismatch. The data was modified between the browser's encryption step and
                the server's decryption step.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Metrics Row */}
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

      {/* ─── Cryptographic & Blockchain Integrity Verification Stats ─── */}
      {hasIntegrityData && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span className="font-medium text-slate-300">Cryptographic Integrity & Forensic Assurance</span>
              {stats.integrity_tampered > 0 && (
                <span className="chip chip-danger text-[10px] animate-pulse">
                  {stats.integrity_tampered} Tampered
                </span>
              )}
            </div>
            <span className="text-mist text-[11px]">Upload envelope transit & immutable blockchain ledger audit</span>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
            <div className="panel p-4 flex flex-col items-center justify-center">
              <div className="text-xs text-mist mb-1">Verified</div>
              <div className="text-2xl font-bold text-emerald-400">{stats.integrity_verified}</div>
              <div className="text-[10px] text-mist mt-1">hash matched & sealed</div>
            </div>
            <div className={`panel p-4 flex flex-col items-center justify-center transition-all ${stats.integrity_tampered > 0 ? 'border-red-500/50 bg-red-500/10' : ''}`}>
              <div className="text-xs text-mist mb-1">Tampered</div>
              <div className={`text-2xl font-bold ${stats.integrity_tampered > 0 ? 'text-red-400 animate-pulse' : 'text-slate-400'}`}>
                {stats.integrity_tampered}
              </div>
              <div className={`text-[10px] mt-1 ${stats.integrity_tampered > 0 ? 'text-red-400 font-medium' : 'text-mist'}`}>
                {stats.integrity_tampered > 0 ? 'tampering detected' : 'zero tampering'}
              </div>
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
        </div>
      )}

      {/* ─── 4-Way Visual Distribution Charts ─── */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Chart 1: By Format */}
        <div className="panel p-4">
          <div className="text-sm font-medium text-slate-200 mb-3">Events by format</div>
          <div className="h-48">
            <Bar
              data={{
                labels: formatLabels,
                datasets: [{ data: formatLabels.map((f) => stats.events_by_format[f]), backgroundColor: CHART_COLORS }],
              }}
              options={chartOptions({ plugins: { legend: { display: false } } })}
            />
          </div>
        </div>

        {/* Chart 2: By Vendor */}
        <div className="panel p-4">
          <div className="text-sm font-medium text-slate-200 mb-3">Events by vendor</div>
          <div className="h-48">
            <Bar
              data={{
                labels: vendorLabels,
                datasets: [{ data: vendorLabels.map((v) => stats.events_by_vendor[v]), backgroundColor: CHART_COLORS }],
              }}
              options={chartOptions({ plugins: { legend: { display: false } } })}
            />
          </div>
        </div>

        {/* Chart 3: By Severity */}
        <div className="panel p-4">
          <div className="text-sm font-medium text-slate-200 mb-3">Events by severity</div>
          <div className="h-48 flex items-center justify-center">
            {severityLabels.length > 0 ? (
              <Doughnut
                data={{
                  labels: severityLabels.map((s) => s.toUpperCase()),
                  datasets: [{
                    data: severityLabels.map((s) => stats.events_by_severity[s]),
                    backgroundColor: severityLabels.map((s) => SEVERITY_COLORS[s.toLowerCase()] || '#475569'),
                  }],
                }}
                options={doughnutOnlyOptions()}
              />
            ) : (
              <div className="text-xs text-mist">No severity data</div>
            )}
          </div>
        </div>

        {/* Chart 4: Processing Status */}
        <div className="panel p-4">
          <div className="text-sm font-medium text-slate-200 mb-3">Processing status</div>
          <div className="h-48 flex items-center justify-center">
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

      {/* Recent Events Table */}
      <div className="panel">
        <div className="flex items-center justify-between px-4 py-3 border-b border-line">
          <div className="text-sm font-medium text-slate-200">Recent events</div>
          <Link to="/events" className="text-xs text-wire hover:underline">
            View all ({stats.processed_events}) →
          </Link>
        </div>
        <table className="w-full text-sm" style={{ tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: '12%' }} />
            <col style={{ width: '12%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '18%' }} />
            <col style={{ width: '26%' }} />
            <col style={{ width: '10%' }} />
            <col style={{ width: '12%' }} />
          </colgroup>
          <thead>
            <tr className="text-left text-xs text-mist border-b border-line">
              <th className="px-4 py-2 font-normal">Time</th>
              <th className="px-4 py-2 font-normal">Vendor</th>
              <th className="px-4 py-2 font-normal">Format</th>
              <th className="px-4 py-2 font-normal">Event type</th>
              <th className="px-4 py-2 font-normal">Source IP</th>
              <th className="px-4 py-2 font-normal">Severity</th>
              <th className="px-4 py-2 font-normal">Status</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id} className="border-b border-line last:border-0 hover:bg-panel2/60 transition-colors">
                <td className="px-4 py-2 mono text-mist whitespace-nowrap">{new Date(e.created_at).toLocaleTimeString()}</td>
                <td className="px-4 py-2 whitespace-nowrap">{e.vendor && e.vendor !== '—' ? e.vendor : 'Unknown'}</td>
                <td className="px-4 py-2 text-mist whitespace-nowrap">{e.format || '—'}</td>
                <td className="px-4 py-2 whitespace-nowrap">
                  <span className="mono text-slate-200">{e.event_type || '—'}</span>
                </td>
                <td className="px-4 py-2 mono overflow-hidden text-ellipsis whitespace-nowrap" title={e.source_ip || ''}>{e.source_ip || '—'}</td>
                <td className="px-4 py-2 whitespace-nowrap">
                  <StatusChip value={e.severity} />
                </td>
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
