import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api.js'
import StatusChip from '../components/StatusChip.jsx'

const STAGES = ['Ingested', 'Format detected', 'Parsed', 'Normalized', 'Validated', 'Stored']

const SAMPLES = {
  'Cisco ASA': '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443',
  Fortigate: 'date=2026-09-11 time=10:35:22 devname="FG01" srcip=10.0.0.5 srcport=51322 dstip=8.8.8.8 dstport=443 proto=6 action="accept" user="jdoe"',
  Linux: 'Sep 11 10:40:12 server01 sshd[1234]: Accepted password for admin from 192.168.1.20 port 54321 ssh2',
  'Windows JSON': '{"EventID": 4624, "Computer": "WIN-SERVER01", "User": "Administrator", "IpAddress": "10.0.0.15", "TimeCreated": "2026-09-11T10:45:00Z"}',
  Apache: '192.168.1.50 - - [11/Sep/2026:10:42:12 +0000] "GET /login HTTP/1.1" 200 1245 "-" "curl/8.0"',
}

function IntegrityChip({ status }) {
  const styles = {
    VERIFIED: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    TAMPERED: 'bg-red-500/15 text-red-400 border-red-500/30 animate-pulse',
    NO_HASH:  'bg-gray-500/15 text-gray-400 border-gray-500/30',
  }
  const labels = {
    VERIFIED: '✓ Hash Verified',
    TAMPERED: '⚠ Tampered',
    NO_HASH:  '— No Hash',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${styles[status] || styles.NO_HASH}`}>
      {labels[status] || status || '—'}
    </span>
  )
}

export default function ProcessLogs() {
  const [rawLog, setRawLog] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [stage, setStage] = useState(-1)
  const [file, setFile] = useState(null)
  const [batchLoading, setBatchLoading] = useState(false)
  const [batchResults, setBatchResults] = useState(null)
  const [batchError, setBatchError] = useState(null)

  async function handleProcess() {
    if (!rawLog.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    setStage(0)

    // Visual pipeline stepper — the actual processing is one backend call,
    // this just walks the stages for a legible demo.
    const tick = (i) => new Promise((r) => setTimeout(() => { setStage(i); r() }, 160))
    for (let i = 1; i <= 3; i++) await tick(i)

    try {
      const res = await api.processLog(rawLog)
      await tick(4)
      await tick(5)
      setResult(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleFileProcess() {
    if (!file) return
    setBatchLoading(true)
    setBatchError(null)
    setBatchResults(null)
    setStage(0)

    try {
      const MAX_FILE_BYTES = 5 * 1024 * 1024
      if (file.size > MAX_FILE_BYTES) {
        throw new Error('File is larger than the 5 MB upload limit.')
      }

      const text = await file.text()
      const rawLogs = text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)

      if (rawLogs.length === 0) throw new Error('The selected file contains no non-empty log lines.')
      if (rawLogs.length > 10000) throw new Error('The selected file contains more than 10,000 log lines.')

      setStage(1)
      const res = await api.processBatchSecure(rawLogs, file.name)
      setStage(5)
      setBatchResults(res)
    } catch (e) {
      setBatchError(e.message)
    } finally {
      setBatchLoading(false)
    }
  }

  const event = result?.event
  const batchSummary = batchResults ? batchResults.reduce((acc, item) => {
    acc.total += 1
    if (item.status === 'UNKNOWN_FORMAT') acc.unknown += 1
    else if (item.status === 'SUCCESS') acc.success += 1
    else if (item.status === 'WARNING') acc.warning += 1
    else acc.failed += 1
    return acc
  }, { total: 0, success: 0, warning: 0, failed: 0, unknown: 0 }) : null

  // Extract the batch-level integrity result from the first item (all items share the same envelope integrity)
  const batchIntegrity = batchResults?.[0]?.integrity || null
  const singleIntegrity = result?.integrity || null

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Process logs</h1>
        <p className="text-sm text-mist mt-1 max-w-2xl">
          Paste one raw log line or upload a log file. ULPF detects the format, runs the
          matching deterministic parser, and normalizes each event into the universal schema.
        </p>
      </div>

      <div className="panel p-4 space-y-3">
        <div className="flex flex-wrap gap-2">
          {Object.entries(SAMPLES).map(([name, sample]) => (
            <button
              key={name}
              className="text-xs px-2.5 py-1 rounded-md bg-panel2 border border-line text-mist hover:text-slate-200 hover:border-wire/50"
              onClick={() => setRawLog(sample)}
            >
              {name} sample
            </button>
          ))}
        </div>
        <textarea
          className="input mono h-24 resize-none"
          placeholder="Paste a raw log line…"
          value={rawLog}
          onChange={(e) => setRawLog(e.target.value)}
        />
        <div className="flex items-center gap-3">
          <button className="btn-primary" onClick={handleProcess} disabled={loading || !rawLog.trim()}>
            {loading ? 'Processing…' : 'Detect format and process'}
          </button>
          {result?.status === 'UNKNOWN_FORMAT' && (
            <Link to="/onboarding" className="text-xs text-wire hover:underline">
              No parser matched — onboard this source →
            </Link>
          )}
        </div>
      </div>

      <div className="panel p-4 space-y-3">
        <div>
          <div className="text-sm font-medium text-slate-200">Upload a log file</div>
          <p className="text-xs text-mist mt-1">
            Upload a .txt, .log, or .csv file. Each non-empty line is treated as one log event.
            The entire batch is encrypted in the browser before it is sent to ULPF.
            A SHA-256 integrity hash is generated before encryption to detect any in-transit tampering.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="file"
            accept=".txt,.log,.csv,text/plain,text/csv"
            className="text-sm text-mist file:mr-3 file:rounded-md file:border file:border-line file:bg-panel2 file:px-3 file:py-2 file:text-sm file:text-slate-200 hover:file:bg-line"
            onChange={(e) => { setFile(e.target.files?.[0] || null); setBatchResults(null); setBatchError(null) }}
          />
          <button className="btn-primary" onClick={handleFileProcess} disabled={batchLoading || !file}>
            {batchLoading ? 'Encrypting & processing…' : 'Encrypt & process file'}
          </button>
        </div>
        {file && <div className="text-xs text-mist">Selected: <span className="mono text-slate-300">{file.name}</span> · {(file.size / 1024).toFixed(1)} KB</div>}
        {batchError && <div className="text-sm text-danger">{batchError}</div>}
      </div>

      {stage >= 0 && (
        <div className="panel p-4">
          <div className="flex items-center gap-2">
            {STAGES.map((s, i) => (
              <React.Fragment key={s}>
                <div
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium ${
                    i <= stage ? 'bg-wire/15 text-wire' : 'bg-panel2 text-mist'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${i <= stage ? 'bg-wire' : 'bg-line'}`} />
                  {s}
                </div>
                {i < STAGES.length - 1 && <div className="flex-1 h-px bg-line" />}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {batchResults && batchSummary && (
        <div className="panel p-4 space-y-4">
          {/* ─── Tamper Alert for Batch ─── */}
          {batchIntegrity && batchIntegrity.integrity_status === 'TAMPERED' && (
            <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3">
              <div className="flex items-start gap-3">
                <span className="text-xl">🛡️</span>
                <div>
                  <div className="text-sm font-semibold text-red-400">
                    Integrity Hash Mismatch — Possible Tampering
                  </div>
                  <p className="text-xs text-red-300/80 mt-1 leading-relaxed">
                    The SHA-256 hash computed by the server after decryption does <strong>not match</strong> the
                    hash generated by the browser before encryption. This batch may have been tampered with in transit.
                  </p>
                  <div className="mt-2 text-[10px] mono text-red-300/60 space-y-0.5">
                    <div>Sent:     {batchIntegrity.integrity_hash_sent}</div>
                    <div>Computed: {batchIntegrity.integrity_hash_computed}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div>
              <div className="text-sm font-medium text-slate-200">Batch processing complete</div>
              <div className="text-xs text-mist mt-1">{batchSummary.total} log lines decrypted and processed.</div>
            </div>
            <div className="flex items-center gap-2">
              <span className="chip chip-success">Encrypted transmission</span>
              {batchIntegrity && <IntegrityChip status={batchIntegrity.integrity_status} />}
            </div>
          </div>

          {/* ─── Integrity Hash Details ─── */}
          {batchIntegrity && (
            <div className={`rounded-md border px-3 py-2 text-xs ${
              batchIntegrity.integrity_status === 'VERIFIED'
                ? 'border-emerald-500/30 bg-emerald-500/5'
                : batchIntegrity.integrity_status === 'TAMPERED'
                  ? 'border-red-500/30 bg-red-500/5'
                  : 'border-gray-500/30 bg-gray-500/5'
            }`}>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-medium text-slate-200">SHA-256 Integrity Verification</span>
                <IntegrityChip status={batchIntegrity.integrity_status} />
              </div>
              <div className="mono text-[10px] text-mist space-y-0.5">
                {batchIntegrity.integrity_hash_sent && (
                  <div>Hash (browser):  {batchIntegrity.integrity_hash_sent}</div>
                )}
                <div>Hash (server):   {batchIntegrity.integrity_hash_computed}</div>
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
            {[["Total", batchSummary.total], ["Processed", batchSummary.success], ["Warnings", batchSummary.warning], ["Failed", batchSummary.failed], ["Unknown", batchSummary.unknown]].map(([label, value]) => (
              <div key={label} className="bg-ink border border-line rounded-md p-3">
                <div className="text-xs text-mist">{label}</div>
                <div className="text-lg font-semibold text-slate-100 mt-1">{value}</div>
              </div>
            ))}
          </div>
          <div className="overflow-auto max-h-80">
            <table className="w-full text-xs">
              <thead className="text-mist border-b border-line">
                <tr><th className="text-left py-2 pr-3">#</th><th className="text-left py-2 pr-3">Status</th><th className="text-left py-2 pr-3">Format</th><th className="text-left py-2 pr-3">Integrity</th><th className="text-left py-2">Log</th></tr>
              </thead>
              <tbody>
                {batchResults.map((item, i) => (
                  <tr key={item.raw_log.id} className="border-b border-line/50">
                    <td className="py-2 pr-3 text-mist">{i + 1}</td>
                    <td className="py-2 pr-3"><StatusChip value={item.status} /></td>
                    <td className="py-2 pr-3 text-mist">{item.raw_log.detected_format || 'unknown'}</td>
                    <td className="py-2 pr-3">
                      <IntegrityChip status={item.raw_log.integrity_status || item.integrity?.integrity_status} />
                    </td>
                    <td className="py-2 mono text-slate-300 max-w-xl truncate">{item.raw_log.raw_content}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      {result && result.status === 'UNKNOWN_FORMAT' && (
        <div className="panel p-4 text-sm text-alert">
          Unknown log format detected. No deterministic or previously generated parser
          matched this line — use Unknown Source Onboarding to teach ULPF this format.
        </div>
      )}

      {event && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="panel p-4 space-y-2">
            <div className="text-xs text-mist mb-1">Detection result</div>
            <div className="flex flex-wrap gap-2 text-sm">
              <span className="chip chip-neutral">{result.raw_log.detected_format}</span>
              {result.raw_log.detected_vendor && (
                <span className="chip chip-neutral">{result.raw_log.detected_vendor}</span>
              )}
              <span className="chip chip-neutral">parser {event.parser_id?.slice(0, 8)}…</span>
              <StatusChip value={event.processing_status} />
              {singleIntegrity && <IntegrityChip status={singleIntegrity.integrity_status} />}
            </div>
            <div className="text-xs text-mist pt-2">Confidence</div>
            <div className="text-lg font-semibold text-signal">
              {Math.round((event.confidence || 0) * 100)}%
            </div>

            {/* ─── Single log integrity details ─── */}
            {singleIntegrity && (
              <div className={`rounded-md border px-3 py-2 text-xs mt-2 ${
                singleIntegrity.integrity_status === 'VERIFIED'
                  ? 'border-emerald-500/30 bg-emerald-500/5'
                  : singleIntegrity.integrity_status === 'TAMPERED'
                    ? 'border-red-500/30 bg-red-500/5'
                    : 'border-gray-500/30 bg-gray-500/5'
              }`}>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-medium text-slate-200">Integrity</span>
                  <IntegrityChip status={singleIntegrity.integrity_status} />
                </div>
                <div className="mono text-[10px] text-mist space-y-0.5">
                  {singleIntegrity.integrity_hash_sent && (
                    <div>Hash (browser):  {singleIntegrity.integrity_hash_sent}</div>
                  )}
                  <div>Hash (server):   {singleIntegrity.integrity_hash_computed}</div>
                </div>
              </div>
            )}

            {(event.validation_warnings?.length > 0) && (
              <div className="pt-2">
                <div className="text-xs text-alert font-medium mb-1">Validation warnings</div>
                <ul className="text-xs text-mist list-disc list-inside space-y-0.5">
                  {event.validation_warnings.map((w, i) => <li key={i}>{w}</li>)}
                </ul>
              </div>
            )}
            <div className="pt-2">
              <Link to={`/traceability?event=${event.id}`} className="text-xs text-wire hover:underline">
                View traceability for this event →
              </Link>
            </div>
          </div>

          <div className="panel p-4">
            <div className="text-xs text-mist mb-2">Normalized event (universal schema)</div>
            <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto max-h-72 text-slate-300">
{JSON.stringify(event.event_data, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {result?.raw_log && (
        <div className="panel p-4">
          <div className="text-xs text-mist mb-2">Raw log (preserved unmodified)</div>
          <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto text-slate-300">{result.raw_log.raw_content}</pre>
        </div>
      )}
    </div>
  )
}

