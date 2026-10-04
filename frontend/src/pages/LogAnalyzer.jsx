import React, { useState } from 'react'
import { api } from '../services/api.js'
import StatusChip from '../components/StatusChip.jsx'
import EditParserModal from '../components/EditParserModal.jsx'

const SAMPLE_TYPES = [
  'Cisco ASA',
  'Fortigate',
  'Linux',
  'Windows JSON',
  'Apache',
  'Unknown',
]

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)]
}

function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min
}

function randomIP() {
  const prefixes = [
    `10.${randomInt(0, 50)}.${randomInt(1, 254)}.${randomInt(1, 254)}`,
    `192.168.${randomInt(1, 100)}.${randomInt(1, 254)}`,
    `172.${randomInt(16, 31)}.${randomInt(1, 254)}.${randomInt(1, 254)}`,
    `203.0.113.${randomInt(1, 254)}`,
    `198.51.100.${randomInt(1, 254)}`,
  ]
  return randomItem(prefixes)
}

function pad2(n) {
  return String(n).padStart(2, '0')
}

function getFormattedTime() {
  const d = new Date(Date.now() - randomInt(0, 3600000))
  const yyyy = d.getFullYear()
  const mm = pad2(d.getMonth() + 1)
  const dd = pad2(d.getDate())
  const hh = pad2(d.getHours())
  const min = pad2(d.getMinutes())
  const ss = pad2(d.getSeconds())
  const ms = String(randomInt(100, 999))
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
  const mmm = months[d.getMonth()]
  return { yyyy, mm, dd, hh, min, ss, ms, mmm, iso: d.toISOString() }
}

function generateUnknownLog() {
  const t = getFormattedTime()
  const users = ['admin', 'jdoe', 'asmith', 'alice_sec', 'bob_ops', 'sreya_dev', 'carlos_m', 'operator_4']
  const verbs = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'CONNECT']
  const paths = ['/api/v1/data', '/api/v2/payment', '/auth/login', '/gateway/orders', '/admin/metrics', '/v1/users/export', '/api/checkout']
  const services = ['order-gateway', 'billing-engine', 'auth-service', 'inventory-api', 'audit-daemon', 'mesh-proxy']
  const hosts = ['PROXY-01', 'GW-INGRESS-02', 'AUTH-SRV-04', 'API-GATEWAY', 'DB-PROXY-01', 'SEC-NODE-12']

  const u = randomItem(users)
  const verb = randomItem(verbs)
  const path = randomItem(paths)
  const svc = randomItem(services)
  const host = randomItem(hosts)
  const srcIp = randomIP()
  const dstIp = randomIP()
  const port = randomItem([80, 443, 8080, 8443, 9200, 5432, 27017])
  const code = randomItem([200, 201, 204, 400, 401, 403, 404, 500, 502, 503])
  const latency = randomInt(5, 450)
  const bytes = randomInt(128, 65536)
  const txnId = `tx_${randomInt(10000, 99999)}`
  const reqId = `rq_${randomInt(100000, 999999)}`
  const sessId = `sess_${randomInt(10000, 99999)}`

  const generators = [
    // Pattern 1: Delimited Gateway Pipe with varying keys
    () => `${t.yyyy}-${t.mm}-${t.dd} ${t.hh}:${t.min}:${t.ss}|${host}|req_id=${reqId}|client=${srcIp}|server=${dstIp}|method=${verb}|endpoint=${path}|status_code=${code}|latency=${latency}ms`,

    // Pattern 2: Bracketed Audit / Microservice Log
    () => `[${t.yyyy}-${t.mm}-${t.dd} ${t.hh}:${t.min}:${t.ss}] [AUDIT-${host}] tenant_id=tenant_${randomInt(100, 999)} actor=${u} client_ip=${srcIp} action=${randomItem(['MODIFY_CONFIG', 'LOGIN_ATTEMPT', 'EXPORT_REPORT', 'PURGE_CACHE', 'GRANT_ACCESS'])} target=${path} outcome=${code < 400 ? 'SUCCESS' : 'FAILURE'}`,

    // Pattern 3: Semicolon Key-Value App Log
    () => `timestamp="${t.iso}"; service="${svc}"; event="${randomItem(['charge_attempt', 'user_verified', 'token_refresh', 'order_submitted'])}"; client_ip="${srcIp}"; target_ip="${dstIp}"; port=${port}; duration=${latency}ms; status="${code < 400 ? 'approved' : 'rejected'}"`,

    // Pattern 4: DB Proxy / Transaction Log
    () => `${t.yyyy}/${t.mm}/${t.dd} ${t.hh}:${t.min}:${t.ss} DB-PROXY-${randomInt(1, 9)}: txn_id=${txnId} db_user=${u} source_ip=${srcIp} operation=${randomItem(['SELECT', 'UPDATE', 'INSERT', 'DELETE'])} table=${randomItem(['customers', 'transactions', 'accounts', 'sessions'])} rows=${randomInt(1, 50)} latency_ms=${latency}`,

    // Pattern 5: Auth Gateway Event
    () => `${t.yyyy}-${t.mm}-${t.dd} ${t.hh}:${t.min}:${t.ss}.${t.ms} AUTH-GATEWAY session_id=${sessId} user_id=${u} origin=${srcIp} auth_type=${randomItem(['MFA_CHALLENGE', 'OAUTH2_CALLBACK', 'PASSWORD_CHECK', 'SSO_SAML'])} result=${code < 400 ? 'VERIFIED' : 'FAILED'} provider=${randomItem(['Okta', 'AzureAD', 'InternalIdP'])}`,

    // Pattern 6: Kubernetes / Mesh Pod Log
    () => `${t.iso} pod="${svc}-${randomInt(10, 99)}x${randomInt(10, 99)}" namespace="${randomItem(['production', 'staging', 'core-services'])}" trace_id="tr_${reqId}" remote_ip="${srcIp}" rpc_method="${randomItem(['ProcessPayment', 'FetchUserProfile', 'ValidateOrder', 'SyncInventory'])}" status_code="${code < 400 ? 'OK' : 'ERROR'}" elapsed="${latency}ms"`,

    // Pattern 7: Network Agent Flow
    () => `${t.yyyy}-${t.mm}-${t.dd} ${t.hh}:${t.min}:${t.ss} NET-FLOW-AGENT: src_ip=${srcIp} src_port=${randomInt(10000, 65000)} dst_ip=${dstIp} dst_port=${port} proto=${randomItem(['TCP', 'UDP'])} bytes_in=${bytes} bytes_out=${randomInt(256, 131072)} flow_state=${randomItem(['ESTABLISHED', 'CLOSED', 'RESET'])}`
  ]

  return randomItem(generators)()
}

function generateSampleLog(type) {
  const t = getFormattedTime()
  const users = ['admin', 'jdoe', 'asmith', 'alice', 'bob']
  const u = randomItem(users)
  const srcIp = randomIP()
  const dstIp = randomIP()
  const srcPort = randomInt(10000, 65000)
  const dstPort = randomItem([80, 443, 8080, 8443])
  const connId = randomInt(10000, 99999)

  switch (type) {
    case 'Cisco ASA': {
      const msgId = randomItem(['302013', '106023'])
      if (msgId === '302013') {
        return `<134>${t.mmm} ${t.dd} ${t.hh}:${t.min}:${t.ss} FW01 %ASA-6-302013: Built outbound TCP connection ${connId} for outside:${srcIp}/${dstPort} to ${dstIp}/${dstPort}`
      }
      return `<134>${t.mmm} ${t.dd} ${t.hh}:${t.min}:${t.ss} FW01 %ASA-4-106023: Deny tcp src outside:${srcIp}/${srcPort} dst inside:${dstIp}/${dstPort} by access-group "OUTSIDE-IN"`
    }
    case 'Fortigate': {
      const action = randomItem(['accept', 'deny', 'close'])
      return `date=${t.yyyy}-${t.mm}-${t.dd} time=${t.hh}:${t.min}:${t.ss} devname="FG01" srcip=${srcIp} srcport=${srcPort} dstip=${dstIp} dstport=${dstPort} proto=6 action="${action}" user="${u}"`
    }
    case 'Linux': {
      const pid = randomInt(1000, 9999)
      const result = randomItem(['Accepted password', 'Failed password'])
      return `${t.mmm} ${t.dd} ${t.hh}:${t.min}:${t.ss} server01 sshd[${pid}]: ${result} for ${u} from ${srcIp} port ${srcPort} ssh2`
    }
    case 'Windows JSON': {
      const eventId = randomItem([4624, 4625, 4634, 4688, 4720])
      return JSON.stringify({
        EventID: eventId,
        Computer: `WIN-SERVER0${randomInt(1, 5)}`,
        User: u === 'admin' ? 'Administrator' : u,
        IpAddress: srcIp,
        TimeCreated: t.iso,
      })
    }
    case 'Apache': {
      const method = randomItem(['GET', 'POST', 'PUT', 'DELETE'])
      const path = randomItem(['/login', '/api/v1/data', '/index.html', '/dashboard', '/products'])
      const status = randomItem([200, 201, 301, 401, 403, 404, 500])
      const size = randomInt(200, 8500)
      const agent = randomItem(['curl/8.0', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'PostmanRuntime/7.32.3'])
      return `${srcIp} - - [${t.dd}/${t.mmm}/${t.yyyy}:${t.hh}:${t.min}:${t.ss} +0000] "${method} ${path} HTTP/1.1" ${status} ${size} "-" "${agent}"`
    }
    case 'Unknown':
    default:
      return generateUnknownLog()
  }
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

function KnownResult({ result, onEditParser }) {
  const [copied, setCopied] = useState(false)

  function handleCopyJSON() {
    navigator.clipboard.writeText(JSON.stringify(result.event?.event_data || {}, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function handleDownloadJSON() {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(result.event?.event_data || {}, null, 2))
    const link = document.createElement('a')
    link.setAttribute('href', dataStr)
    link.setAttribute('download', `normalized_event_${result.event?.id || Date.now()}.json`)
    link.click()
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <FormatBadge status="KNOWN" />
        {result.integrity && <IntegrityChip status={result.integrity.integrity_status} />}
      </div>

      {/* Parser details */}
      <div className="panel p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="text-sm font-medium text-slate-200">Parser Details</div>
          {result.parser_name && (
            <button
              type="button"
              onClick={() => onEditParser && onEditParser(result.parser_name)}
              className="text-xs px-2.5 py-1 rounded bg-panel2 border border-line text-slate-200 hover:border-wire hover:text-wire transition-colors flex items-center gap-1.5"
              title="Edit this parser's configuration and fields"
            >
              ✏️ Edit Parser
            </button>
          )}
        </div>
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
          <div className="flex items-center justify-between mb-2">
            <div className="text-sm font-medium text-slate-200">Normalized Event (Universal Schema)</div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyJSON}
                className="text-xs px-2.5 py-1 rounded bg-panel2 border border-line text-mist hover:text-slate-200 transition-colors"
              >
                {copied ? '✓ Copied' : 'Copy JSON'}
              </button>
              <button
                onClick={handleDownloadJSON}
                className="text-xs px-2.5 py-1 rounded bg-panel2 border border-line text-mist hover:text-slate-200 transition-colors"
              >
                Download JSON
              </button>
            </div>
          </div>
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

function UnknownResult({ result, onApprove, onEditParser }) {
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

  function exportSchema() {
    const schema = {
      proposed_parser_name: parserName || selectedParser || 'custom_parser',
      sample_log: result.raw_log,
      fields: editableFields.filter((f) => !f._excluded).map(({ _excluded, ...rest }) => rest),
      classifier: 'ULPF Offline RandomForest Token Classifier',
      generated_at: new Date().toISOString(),
    }
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(schema, null, 2))
    const link = document.createElement('a')
    link.setAttribute('href', dataStr)
    link.setAttribute('download', `proposed_parser_${schema.proposed_parser_name}_${Date.now()}.json`)
    link.click()
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
          <div className="px-4 py-3 border-b border-line flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-slate-200">ML-Discovered Fields</div>
              <div className="text-xs text-mist mt-0.5">
                Fields discovered by heuristic analysis and local ML. Toggle to include/exclude before approval.
              </div>
            </div>
            <button
              onClick={exportSchema}
              className="text-xs px-2.5 py-1 rounded bg-panel2 border border-line text-mist hover:text-slate-200 hover:border-wire transition-colors"
              title="Download proposed parser JSON configuration"
            >
              Export Schema (JSON)
            </button>
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
                <th className="px-4 py-2 font-normal text-right">Actions</th>
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
                  <td className="px-4 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => onEditParser && onEditParser(c.parser_name)}
                      className="text-[11px] px-2 py-0.5 rounded bg-panel2 border border-line text-slate-300 hover:text-wire hover:border-wire transition-colors"
                      title={`Edit ${c.parser_name}`}
                    >
                      Edit
                    </button>
                  </td>
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
          <div className="flex items-center justify-between">
            <div className="text-sm font-medium text-signal">✓ {approveResult.message}</div>
            <button
              type="button"
              onClick={() => onEditParser && onEditParser(approveResult.parser_name)}
              className="text-xs px-2.5 py-1 rounded bg-wire/15 border border-wire/40 text-wire hover:bg-wire/25 transition-colors"
            >
              ✏️ Edit Parser
            </button>
          </div>
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

function BatchResults({ batchResult, onEditParser }) {
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
                  <th className="text-right py-2 px-3">Actions</th>
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
                    <td className="py-2 px-3 text-right">
                      {r.parser_name && (
                        <button
                          type="button"
                          onClick={() => onEditParser && onEditParser(r.parser_name)}
                          className="text-[11px] px-2 py-0.5 rounded bg-panel2 border border-line text-slate-300 hover:text-wire hover:border-wire transition-colors"
                        >
                          Edit
                        </button>
                      )}
                    </td>
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
          <UnknownResult result={unknownResult} onEditParser={onEditParser} />
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
  const [editingParserData, setEditingParserData] = useState(null)
  const [editBusy, setEditBusy] = useState(false)
  const [analyzerToast, setAnalyzerToast] = useState(null)

  async function handleOpenEditParser(parserIdentifier) {
    try {
      const p = await api.getParser(parserIdentifier)
      setEditingParserData(p)
    } catch (err) {
      setAnalyzerToast({ msg: `Failed to load parser: ${err.message}`, type: 'danger' })
      setTimeout(() => setAnalyzerToast(null), 4000)
    }
  }

  async function handleSaveParser(payload) {
    if (!editingParserData) return
    setEditBusy(true)
    try {
      const updated = await api.updateParser(editingParserData.id, payload)
      setEditingParserData(null)
      setAnalyzerToast({ msg: `Parser '${updated.name}' updated successfully!`, type: 'success' })
      setTimeout(() => setAnalyzerToast(null), 4000)
      if (result && result.parser_name === editingParserData.name) {
        setResult((prev) => ({
          ...prev,
          parser_name: updated.name,
        }))
      }
    } catch (err) {
      setAnalyzerToast({ msg: `Failed to update parser: ${err.message}`, type: 'danger' })
      setTimeout(() => setAnalyzerToast(null), 4000)
    } finally {
      setEditBusy(false)
    }
  }

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
          {SAMPLE_TYPES.map((name) => {
            const isUnknown = name === 'Unknown'
            return (
              <button
                key={name}
                className={`text-xs px-2.5 py-1 rounded-md border transition-colors ${
                  isUnknown
                    ? 'bg-amber-500/10 border-amber-500/30 text-amber-300 hover:bg-amber-500/20 hover:border-amber-400 font-medium'
                    : 'bg-panel2 border border-line text-mist hover:text-slate-200 hover:border-wire/50'
                }`}
                onClick={() => {
                  const log = generateSampleLog(name)
                  setRawLog(log)
                  setResult(null)
                  setError(null)
                }}
                title={isUnknown ? 'Click to generate a randomized unknown log' : `Generate sample ${name} log`}
              >
                {name}
              </button>
            )
          })}
        </div>
        <textarea
          className="input mono h-24 resize-none"
          placeholder="Paste a raw log line…"
          value={rawLog}
          onChange={(e) => setRawLog(e.target.value)}
        />
        <div className="flex items-center gap-2">
          <button className="btn-primary" onClick={handleAnalyze} disabled={loading || !rawLog.trim()}>
            {loading ? 'Analyzing…' : 'Analyze log'}
          </button>
          {rawLog && (
            <button
              className="text-xs px-3 py-1.5 rounded-md bg-panel2 border border-line text-mist hover:text-slate-200 transition-colors"
              onClick={() => { setRawLog(''); setResult(null); setError(null) }}
            >
              Clear
            </button>
          )}
        </div>
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

      {/* Toast Notification */}
      {analyzerToast && (
        <div
          className={`fixed top-4 right-4 z-50 px-4 py-2.5 rounded-lg shadow-lg text-xs font-medium border transition-all ${
            analyzerToast.type === 'danger'
              ? 'bg-red-500/20 text-red-300 border-red-500/40'
              : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
          }`}
        >
          {analyzerToast.msg}
        </div>
      )}

      {/* Edit Parser Modal */}
      {editingParserData && (
        <EditParserModal
          parser={editingParserData}
          busy={editBusy}
          onSave={handleSaveParser}
          onClose={() => setEditingParserData(null)}
        />
      )}

      {/* Error */}
      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      {/* Single log result */}
      {result && result.format_status === 'KNOWN' && (
        <KnownResult result={result} onEditParser={handleOpenEditParser} />
      )}
      {result && result.format_status === 'UNKNOWN' && (
        <UnknownResult result={result} onEditParser={handleOpenEditParser} />
      )}

      {/* Batch results */}
      {batchResult && (
        <BatchResults batchResult={batchResult} onEditParser={handleOpenEditParser} />
      )}
    </div>
  )
}
