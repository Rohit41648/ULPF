import React, { useState } from 'react'
import { api } from '../services/api.js'
import StatusChip from '../components/StatusChip.jsx'

const SAMPLES = {
  'Cisco ASA': '<134>Sep 11 10:32:14 FW01 %ASA-6-302013: Built outbound TCP connection 12345 for outside:192.168.1.10/443 to 8.8.8.8/443',
  Fortigate: 'date=2026-09-11 time=10:35:22 devname="FG01" srcip=10.0.0.5 srcport=51322 dstip=8.8.8.8 dstport=443 proto=6 action="accept" user="jdoe"',
  Linux: 'Sep 11 10:40:12 server01 sshd[1234]: Accepted password for admin from 192.168.1.20 port 54321 ssh2',
  'Windows JSON': '{"EventID": 4624, "Computer": "WIN-SERVER01", "User": "Administrator", "IpAddress": "10.0.0.15", "TimeCreated": "2026-09-11T10:45:00Z"}',
  Apache: '192.168.1.50 - - [11/Sep/2026:10:42:12 +0000] "GET /login HTTP/1.1" 200 1245 "-" "curl/8.0"',
  'Unknown (pipe)': '2026-09-11 10:50:00|PROXY-01|principal=jdoe|src=10.0.0.99|dst=203.0.113.5|verb=CONNECT|uri=/api/v1/data|code=200',
}

function IntegrityChip({ status }) {
  const styles = {
    VERIFIED: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    TAMPERED: 'bg-red-500/15 text-red-400 border-red-500/30 animate-pulse',
    NO_HASH:  'bg-gray-500/15 text-gray-400 border-gray-500/30',
  }
  const labels = { VERIFIED: '✓ Verified', TAMPERED: '⚠ Tampered', NO_HASH: '— No Hash' }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border ${styles[status] || styles.NO_HASH}`}>
      {labels[status] || status || '—'}
    </span>
  )
}

function FormatBadge({ status }) {
  const isKnown = status === 'KNOWN'
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${
      isKnown
        ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
        : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
    }`}>
      <span className={`w-2 h-2 rounded-full ${isKnown ? 'bg-emerald-400' : 'bg-amber-400'}`} />
      {isKnown ? 'Known Log Format' : 'Unknown Log Format'}
    </span>
  )
}

// ── Known format result display ─────────────────────────────────────────

function KnownResult({ result }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <FormatBadge status="KNOWN" />
        {result.integrity && <IntegrityChip status={result.integrity.integrity_status} />}
      </div>

      {/* Parser details */}
      <div className="panel p-4">
        <div className="text-sm font-medium text-slate-200 mb-3">Parser Details</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            ['Parser name', result.parser_name],
            ['Version', result.parser_version],
            ['Format', result.detected_format],
            ['Vendor', result.detected_vendor || '—'],
          ].map(([label, value]) => (
            <div key={label}>
              <div className="text-xs text-mist">{label}</div>
              <div className="text-sm text-slate-200 mt-0.5 mono">{value}</div>
            </div>
          ))}
        </div>
        <div className="mt-3 flex items-center gap-2">
          <div className="text-xs text-mist">Confidence</div>
          <div className="flex-1 h-2 bg-ink rounded-full overflow-hidden">
            <div
              className="h-full bg-signal rounded-full transition-all"
              style={{ width: `${Math.round(result.confidence * 100)}%` }}
            />
          </div>
          <div className="text-sm font-semibold text-signal">{Math.round(result.confidence * 100)}%</div>
        </div>
      </div>

      {/* Field mapping table */}
      {result.fields?.length > 0 && (
        <div className="panel overflow-hidden">
          <div className="px-4 py-3 border-b border-line">
            <div className="text-sm font-medium text-slate-200">Field Mapping to Universal Schema</div>
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-mist border-b border-line">
                <th className="px-4 py-2 font-normal">Field</th>
                <th className="px-4 py-2 font-normal">Value</th>
                <th className="px-4 py-2 font-normal">Maps to</th>
                <th className="px-4 py-2 font-normal">Data type</th>
                <th className="px-4 py-2 font-normal">Source</th>
              </tr>
            </thead>
            <tbody>
              {result.fields.map((f, i) => (
                <tr key={i} className="border-b border-line/50 last:border-0">
                  <td className="px-4 py-2 mono text-slate-200">{f.field}</td>
                  <td className="px-4 py-2 mono text-mist max-w-xs truncate">{f.value || '—'}</td>
                  <td className="px-4 py-2 text-wire">{f.mapped_to}</td>
                  <td className="px-4 py-2 text-mist">{f.data_type}</td>
                  <td className="px-4 py-2"><span className="chip chip-neutral">{f.source}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Normalized event */}
      {result.event && (
        <div className="panel p-4">
          <div className="text-sm font-medium text-slate-200 mb-2">Normalized Event (Universal Schema)</div>
          <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto max-h-64 text-slate-300">
{JSON.stringify(result.event.event_data, null, 2)}
          </pre>
        </div>
      )}

      {/* Integrity details */}
      {result.integrity && (
        <div className={`panel p-4 border ${
          result.integrity.integrity_status === 'VERIFIED'
            ? 'border-emerald-500/30'
            : result.integrity.integrity_status === 'TAMPERED'
              ? 'border-red-500/30'
              : 'border-line'
        }`}>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-sm font-medium text-slate-200">SHA-256 Integrity Verification</span>
            <IntegrityChip status={result.integrity.integrity_status} />
          </div>
          <div className="mono text-[10px] text-mist space-y-0.5">
            {result.integrity.integrity_hash_sent && <div>Hash (browser):  {result.integrity.integrity_hash_sent}</div>}
            <div>Hash (server):   {result.integrity.integrity_hash_computed}</div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Unknown format result display ───────────────────────────────────────

function UnknownResult({ result, onApprove }) {
  const [selectedAction, setSelectedAction] = useState(null)
  const [parserName, setParserName] = useState('')
  const [selectedParser, setSelectedParser] = useState(result.parser_candidates?.[0]?.parser_name || '')
  const [editableFields, setEditableFields] = useState(result.fields || [])
  const [approving, setApproving] = useState(false)
  const [approveResult, setApproveResult] = useState(null)
  const [approveError, setApproveError] = useState(null)

  const topCandidate = result.parser_candidates?.[0]

  function handleFieldToggle(index) {
    setEditableFields((prev) => {
      const copy = [...prev]
      copy[index] = { ...copy[index], _excluded: !copy[index]._excluded }
      return copy
    })
  }

  async function handleApprove() {
    if (!selectedAction) return
    const name = selectedAction === 'extend_parser' ? selectedParser : parserName
    if (!name.trim()) return
    setApproving(true)
    setApproveError(null)
    try {
      const fields = editableFields
        .filter((f) => !f._excluded)
        .map(({ _excluded, ...rest }) => rest)
      const res = await api.approveAction(selectedAction, result.raw_log, name, fields)
      setApproveResult(res)
      if (onApprove) onApprove(res)
    } catch (e) {
      setApproveError(e.message)
    } finally {
      setApproving(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <FormatBadge status="UNKNOWN" />
        {result.integrity && <IntegrityChip status={result.integrity.integrity_status} />}
        <span className="text-xs text-mist">
          Overall confidence: <strong className="text-amber-400">{Math.round(result.confidence * 100)}%</strong>
        </span>
      </div>

      {/* Discovered fields */}
      {result.fields?.length > 0 && (
        <div className="panel overflow-hidden">
          <div className="px-4 py-3 border-b border-line">
            <div className="text-sm font-medium text-slate-200">AI-Discovered Fields</div>
            <div className="text-xs text-mist mt-0.5">
              Fields discovered by heuristic analysis and AI. Toggle to include/exclude before approval.
            </div>
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-mist border-b border-line">
                <th className="px-4 py-2 font-normal w-8">Use</th>
                <th className="px-4 py-2 font-normal">Field</th>
                <th className="px-4 py-2 font-normal">Value</th>
                <th className="px-4 py-2 font-normal">Suggested mapping</th>
                <th className="px-4 py-2 font-normal">Data type</th>
                <th className="px-4 py-2 font-normal">Confidence</th>
                <th className="px-4 py-2 font-normal">Source</th>
              </tr>
            </thead>
            <tbody>
              {editableFields.map((f, i) => (
                <tr key={i} className={`border-b border-line/50 last:border-0 ${f._excluded ? 'opacity-40' : ''}`}>
                  <td className="px-4 py-2">
                    <input
                      type="checkbox"
                      checked={!f._excluded}
                      onChange={() => handleFieldToggle(i)}
                      className="accent-wire"
                    />
                  </td>
                  <td className="px-4 py-2 mono text-slate-200">{f.field}</td>
                  <td className="px-4 py-2 mono text-mist max-w-xs truncate">{f.value || '—'}</td>
                  <td className="px-4 py-2 text-wire">{f.mapped_to}</td>
                  <td className="px-4 py-2 text-mist">{f.data_type}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-1.5">
                      <div className="w-12 h-1.5 bg-ink rounded-full overflow-hidden">
                        <div className="h-full bg-amber-400/60 rounded-full" style={{ width: `${Math.round(f.confidence * 100)}%` }} />
                      </div>
                      <span className="text-mist">{Math.round(f.confidence * 100)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-2"><span className="chip chip-neutral">{f.source}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Parser candidates */}
      {result.parser_candidates?.length > 0 && (
        <div className="panel overflow-hidden">
          <div className="px-4 py-3 border-b border-line">
            <div className="text-sm font-medium text-slate-200">Existing Parser Candidates</div>
            <div className="text-xs text-mist mt-0.5">
              Comparison of the unknown log against existing parser engines and schema profiles.
            </div>
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-mist border-b border-line">
                <th className="px-4 py-2 font-normal">Parser</th>
                <th className="px-4 py-2 font-normal">Format</th>
                <th className="px-4 py-2 font-normal">Vendor</th>
                <th className="px-4 py-2 font-normal">Match %</th>
                <th className="px-4 py-2 font-normal">Matched fields</th>
                <th className="px-4 py-2 font-normal">Unmatched fields</th>
                <th className="px-4 py-2 font-normal">Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {result.parser_candidates.map((c, i) => (
                <tr key={i} className={`border-b border-line/50 last:border-0 ${i === 0 ? 'bg-wire/5' : ''}`}>
                  <td className="px-4 py-2 mono text-slate-200">{c.parser_name}</td>
                  <td className="px-4 py-2 text-mist">{c.parser_format || '—'}</td>
                  <td className="px-4 py-2 text-mist">{c.vendor || '—'}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-1.5">
                      <div className="w-16 h-1.5 bg-ink rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${c.match_percentage >= 70 ? 'bg-signal' : c.match_percentage >= 40 ? 'bg-amber-400' : 'bg-danger/60'}`}
                          style={{ width: `${c.match_percentage}%` }}
                        />
                      </div>
                      <span className="text-slate-200 font-medium">{c.match_percentage}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {c.matched_fields.map((f) => (
                        <span key={f} className="chip chip-success text-[9px]">{f}</span>
                      ))}
                      {c.matched_fields.length === 0 && <span className="text-mist">—</span>}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {c.unmatched_fields.map((f) => (
                        <span key={f} className="chip chip-warning text-[9px]">{f}</span>
                      ))}
                      {c.unmatched_fields.length === 0 && <span className="text-mist">—</span>}
                    </div>
                  </td>
                  <td className="px-4 py-2 text-mist text-[10px] max-w-[180px]">{c.recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Human approval actions */}
      {!approveResult && (
        <div className="panel p-4 space-y-4">
          <div className="text-sm font-medium text-slate-200">Action — Human Approval Required</div>
          <p className="text-xs text-mist">
            The system will <strong>not</strong> automatically modify any existing parser or schema.
            Choose an action below and review before confirming.
          </p>
          <div className="flex flex-wrap gap-2">
            {topCandidate && (
              <button
                className={`btn-secondary text-xs ${selectedAction === 'extend_parser' ? '!bg-wire/20 !border-wire !text-wire' : ''}`}
                onClick={() => { setSelectedAction('extend_parser'); setSelectedParser(topCandidate.parser_name) }}
              >
                Extend existing parser
              </button>
            )}
            <button
              className={`btn-secondary text-xs ${selectedAction === 'create_parser' ? '!bg-wire/20 !border-wire !text-wire' : ''}`}
              onClick={() => setSelectedAction('create_parser')}
            >
              Create new parser
            </button>
          </div>

          {selectedAction === 'extend_parser' && (
            <div className="space-y-2">
              <label className="text-xs text-mist">Select parser to extend</label>
              <select
                className="input w-64"
                value={selectedParser}
                onChange={(e) => setSelectedParser(e.target.value)}
              >
                {result.parser_candidates.map((c) => (
                  <option key={c.parser_name} value={c.parser_name}>
                    {c.parser_name} ({c.match_percentage}% match)
                  </option>
                ))}
              </select>
            </div>
          )}

          {selectedAction === 'create_parser' && (
            <div className="space-y-2">
              <label className="text-xs text-mist">New parser name</label>
              <input
                className="input w-64"
                placeholder="e.g. proxy_kv_v1"
                value={parserName}
                onChange={(e) => setParserName(e.target.value)}
              />
            </div>
          )}

          {selectedAction && (
            <div className="flex items-center gap-3">
              <button
                className="btn-primary"
                onClick={handleApprove}
                disabled={approving || (selectedAction === 'create_parser' && !parserName.trim())}
              >
                {approving ? 'Saving…' : `Confirm — ${selectedAction === 'extend_parser' ? 'Extend' : 'Create'} parser`}
              </button>
              <button className="btn-secondary text-xs" onClick={() => setSelectedAction(null)}>
                Cancel
              </button>
            </div>
          )}

          {approveError && <div className="text-sm text-danger">{approveError}</div>}
        </div>
      )}

      {approveResult && (
        <div className="panel p-4 border border-signal/30 bg-signal/5">
          <div className="text-sm font-medium text-signal">✓ {approveResult.message}</div>
          <div className="text-xs text-mist mt-1">
            Parser <span className="mono text-slate-200">{approveResult.parser_name}</span> has been {approveResult.action === 'extended' ? 'extended' : 'created'}.
            Future logs matching this pattern will be processed automatically.
          </div>
        </div>
      )}
    </div>
  )
}

// ── Batch results display ───────────────────────────────────────────────

function BatchResults({ batchResult }) {
  const { results, summary, integrity } = batchResult

  // Separate known results from the unified unknown result
  const knownResults = results.filter((r) => r.format_status === 'KNOWN')
  const unknownResult = results.find((r) => r.format_status === 'UNKNOWN')

  return (
    <div className="space-y-4">
      {/* Tamper alert */}
      {integrity?.integrity_status === 'TAMPERED' && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-5 py-4">
          <div className="flex items-start gap-3">
            <span className="text-2xl">🛡️</span>
            <div>
              <div className="text-sm font-semibold text-red-400">Integrity Hash Mismatch — Possible Tampering</div>
              <p className="text-xs text-red-300/80 mt-1">
                The SHA-256 hash computed by the server does <strong>not match</strong> the hash generated by the browser.
              </p>
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <div className="text-sm font-medium text-slate-200">Batch analysis complete</div>
          <div className="text-xs text-mist mt-1">{summary.total} log lines analyzed</div>
        </div>
        <div className="flex items-center gap-2">
          <span className="chip chip-success">AES-256-GCM encrypted</span>
          {integrity && <IntegrityChip status={integrity.integrity_status} />}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-2">
        {[['Total', summary.total, ''], ['Known formats', summary.known, 'text-emerald-400'], ['Unknown formats', summary.unknown, 'text-amber-400']].map(([label, value, accent]) => (
          <div key={label} className="bg-ink border border-line rounded-md p-3">
            <div className="text-xs text-mist">{label}</div>
            <div className={`text-lg font-semibold mt-1 ${accent || 'text-slate-100'}`}>{value}</div>
          </div>
        ))}
      </div>

      {/* Known results table */}
      {knownResults.length > 0 && (
        <div className="panel overflow-hidden">
          <div className="px-4 py-3 border-b border-line">
            <div className="text-sm font-medium text-slate-200">Known Format Logs</div>
            <div className="text-xs text-mist mt-0.5">{knownResults.length} log{knownResults.length !== 1 ? 's' : ''} matched existing parsers</div>
          </div>
          <div className="overflow-auto max-h-96">
            <table className="w-full text-xs">
              <thead className="text-mist border-b border-line sticky top-0 bg-panel">
                <tr>
                  <th className="text-left py-2 px-3">#</th>
                  <th className="text-left py-2 px-3">Status</th>
                  <th className="text-left py-2 px-3">Format</th>
                  <th className="text-left py-2 px-3">Parser</th>
                  <th className="text-left py-2 px-3">Confidence</th>
                  <th className="text-left py-2 px-3">Fields</th>
                  <th className="text-left py-2 px-3">Log</th>
                </tr>
              </thead>
              <tbody>
                {knownResults.map((r, i) => (
                  <tr key={i} className="border-b border-line/50 last:border-0">
                    <td className="py-2 px-3 text-mist">{i + 1}</td>
                    <td className="py-2 px-3"><FormatBadge status={r.format_status} /></td>
                    <td className="py-2 px-3 text-mist">{r.detected_format || '—'}</td>
                    <td className="py-2 px-3 mono text-slate-200">{r.parser_name || '—'}</td>
                    <td className="py-2 px-3 text-slate-200">{Math.round(r.confidence * 100)}%</td>
                    <td className="py-2 px-3 text-mist">{r.fields?.length || 0}</td>
                    <td className="py-2 px-3 mono text-slate-300 max-w-xs truncate">{r.raw_log}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Unified unknown analysis */}
      {unknownResult && (
        <div className="space-y-4">
          <div className="panel p-4 border border-amber-500/30 bg-amber-500/5">
            <div className="flex items-center gap-2 mb-1">
              <FormatBadge status="UNKNOWN" />
              <span className="text-xs text-mist">
                {(unknownResult.unknown_raw_logs?.length || 1)} unknown log{(unknownResult.unknown_raw_logs?.length || 1) !== 1 ? 's' : ''} analysed together
              </span>
            </div>
            <p className="text-xs text-mist mt-1">
              Fields discovered across all unknown lines were unioned to find the best-matching existing parser.
              You can extend an existing parser or create a new one below.
            </p>
          </div>

          {/* Unknown raw logs list */}
          {unknownResult.unknown_raw_logs?.length > 0 && (
            <div className="panel overflow-hidden">
              <div className="px-4 py-3 border-b border-line">
                <div className="text-sm font-medium text-slate-200">Unknown Log Lines</div>
                <div className="text-xs text-mist mt-0.5">{unknownResult.unknown_raw_logs.length} lines did not match any parser</div>
              </div>
              <div className="overflow-auto max-h-48 p-3">
                {unknownResult.unknown_raw_logs.map((line, i) => (
                  <div key={i} className="mono text-[11px] text-slate-300 py-1 border-b border-line/30 last:border-0 truncate">
                    <span className="text-mist mr-2">{i + 1}.</span>{line}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Render the unknown result with approval actions */}
          <UnknownResult result={unknownResult} />
        </div>
      )}
    </div>
  )
}

// ── Main LogAnalyzer page ───────────────────────────────────────────────

export default function LogAnalyzer() {
  const [rawLog, setRawLog] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [file, setFile] = useState(null)
  const [batchLoading, setBatchLoading] = useState(false)
  const [batchResult, setBatchResult] = useState(null)
  const [batchError, setBatchError] = useState(null)

  async function handleAnalyze() {
    if (!rawLog.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await api.analyzeLog(rawLog.trim())
      setResult(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleFileAnalyze() {
    if (!file) return
    setBatchLoading(true)
    setBatchError(null)
    setBatchResult(null)
    try {
      if (file.size > 5 * 1024 * 1024) throw new Error('File exceeds 5 MB limit.')
      const text = await file.text()
      const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)
      if (lines.length === 0) throw new Error('File contains no non-empty lines.')
      if (lines.length > 10000) throw new Error('File contains more than 10,000 lines.')
      const res = await api.analyzeBatchSecure(lines, file.name)
      setBatchResult(res)
    } catch (e) {
      setBatchError(e.message)
    } finally {
      setBatchLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Log Analyzer</h1>
        <p className="text-sm text-mist mt-1 max-w-2xl">
          Paste a sample log or upload a log file. ULPF auto-detects whether the format is
          <strong className="text-emerald-400"> known </strong> or
          <strong className="text-amber-400"> unknown</strong>, runs the appropriate analysis,
          and lets you take action on unknown formats.
        </p>
      </div>

      {/* Sample log input */}
      <div className="panel p-4 space-y-3">
        <div className="text-sm font-medium text-slate-200">Enter a sample log</div>
        <div className="flex flex-wrap gap-2">
          {Object.entries(SAMPLES).map(([name, sample]) => (
            <button
              key={name}
              className="text-xs px-2.5 py-1 rounded-md bg-panel2 border border-line text-mist hover:text-slate-200 hover:border-wire/50 transition-colors"
              onClick={() => { setRawLog(sample); setResult(null); setError(null) }}
            >
              {name}
            </button>
          ))}
        </div>
        <textarea
          className="input mono h-24 resize-none"
          placeholder="Paste a raw log line…"
          value={rawLog}
          onChange={(e) => setRawLog(e.target.value)}
        />
        <button className="btn-primary" onClick={handleAnalyze} disabled={loading || !rawLog.trim()}>
          {loading ? 'Analyzing…' : 'Analyze log'}
        </button>
      </div>

      {/* File upload */}
      <div className="panel p-4 space-y-3">
        <div className="text-sm font-medium text-slate-200">Upload a log file</div>
        <p className="text-xs text-mist">
          Upload a .txt, .log, or .csv file. Known-format lines are processed individually.
          Unknown-format lines are analysed together — their fields are unioned so you can
          create or extend a parser for the whole batch. AES-256-GCM encryption + SHA-256 integrity.
        </p>
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="file"
            accept=".txt,.log,.csv,text/plain,text/csv"
            className="text-sm text-mist file:mr-3 file:rounded-md file:border file:border-line file:bg-panel2 file:px-3 file:py-2 file:text-sm file:text-slate-200 hover:file:bg-line"
            onChange={(e) => { setFile(e.target.files?.[0] || null); setBatchResult(null); setBatchError(null) }}
          />
          <button className="btn-primary" onClick={handleFileAnalyze} disabled={batchLoading || !file}>
            {batchLoading ? 'Encrypting & analyzing…' : 'Encrypt & analyze file'}
          </button>
        </div>
        {file && <div className="text-xs text-mist">Selected: <span className="mono text-slate-300">{file.name}</span> · {(file.size / 1024).toFixed(1)} KB</div>}
        {batchError && <div className="text-sm text-danger mt-2">{batchError}</div>}
      </div>

      {/* Error */}
      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      {/* Single log result */}
      {result && result.format_status === 'KNOWN' && <KnownResult result={result} />}
      {result && result.format_status === 'UNKNOWN' && <UnknownResult result={result} />}

      {/* Batch results */}
      {batchResult && <BatchResults batchResult={batchResult} />}
    </div>
  )
}
