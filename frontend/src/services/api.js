import { encryptPayload } from './secureCrypto.js'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  const isJson = res.headers.get('content-type')?.includes('application/json')
  const body = isJson ? await res.json() : null
  if (!res.ok) {
    const detail = body?.detail || res.statusText
    const err = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    err.status = res.status
    err.body = body
    throw err
  }
  return body
}

/**
 * Encrypt payload with the shared AES key (fetched over HTTPS) and send.
 */
async function secureRequest(path, payload) {
  const envelope = await encryptPayload(payload, async () => {
    return request('/security/encryption-key')
  })
  return request(path, { method: 'POST', body: JSON.stringify(envelope) })
}

export const api = {
  health: () => request('/health'),
  stats: () => request('/stats'),

  listLogs: (limit = 50) => request(`/logs?limit=${limit}`),
  getLog: (id) => request(`/logs/${id}`),
  ingestLog: (raw_log, source_hint) =>
    request('/logs/ingest', { method: 'POST', body: JSON.stringify({ raw_log, source_hint }) }),
  processLog: (raw_log, source_hint) =>
    secureRequest('/logs/secure-process', { raw_log, source_hint }),
  processBatch: (raw_logs, source_hint) =>
    request('/logs/process/batch', { method: 'POST', body: JSON.stringify({ raw_logs, source_hint }) }),
  processBatchSecure: (raw_logs, source_hint) =>
    secureRequest('/logs/secure-process-batch', { raw_logs, source_hint }),

  listEvents: (params = {}) => {
    const qs = new URLSearchParams(params).toString()
    return request(`/events${qs ? `?${qs}` : ''}`)
  },
  getEvent: (id) => request(`/events/${id}`),
  getEventTrace: (id) => request(`/events/${id}/trace`),
  updateEvent: (id, payload) =>
    request(`/events/${id}`, { method: 'PATCH', body: JSON.stringify(payload) }),
  deleteEvent: (id) => request(`/events/${id}`, { method: 'DELETE' }),
  bulkDeleteEvents: (event_ids) =>
    request('/events/bulk-delete', { method: 'POST', body: JSON.stringify({ event_ids }) }),

  listParsers: () => request('/parsers'),
  getParser: (id) => request(`/parsers/${id}`),
  updateParser: (id, payload) =>
    request(`/parsers/${id}`, { method: 'PATCH', body: JSON.stringify(payload) }),
  deleteParser: (id) => request(`/parsers/${id}`, { method: 'DELETE' }),
  testParser: (id, raw_log) =>
    request(`/parsers/${id}/test`, { method: 'POST', body: JSON.stringify({ raw_log }) }),

  // ── Blockchain Integrity Ledger ──
  blockchainStatus: () => request('/blockchain/status'),
  blockchainBlocks: () => request('/blockchain/blocks'),
  blockchainVerifyEvent: (event_id) => request(`/blockchain/verify/${event_id}`),

  // ── Engine Health / Debug ──
  debugML: () => request('/analyzer/debug-ml'),

  // ── Unified Log Analyzer ──
  analyzeLog: (raw_log) =>
    request('/analyzer/analyze', { method: 'POST', body: JSON.stringify({ raw_log }) }),
  analyzeLogSecure: (raw_log) =>
    secureRequest('/analyzer/analyze-secure', { raw_log }),
  analyzeBatchSecure: (raw_logs, source_hint) =>
    secureRequest('/analyzer/analyze-batch-secure', { raw_logs, source_hint }),
  approveAction: (action, raw_log, parser_name, approved_fields) =>
    request('/analyzer/approve', {
      method: 'POST',
      body: JSON.stringify({ action, raw_log, parser_name, approved_fields }),
    }),

  // ── Legacy onboarding (kept for backward compat) ──
  analyzeUnknown: (raw_log) =>
    secureRequest('/onboarding/analyze-secure', { raw_log }),
  createParser: (raw_log, parser_name, approved_fields) =>
    secureRequest('/onboarding/create-parser-secure', { raw_log, parser_name, approved_fields }),
}
