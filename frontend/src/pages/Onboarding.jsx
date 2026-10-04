import React, { useState } from 'react'
import { api } from '../services/api.js'
import StatusChip from '../components/StatusChip.jsx'

const SAMPLE = '2026/09/11 10:51:23 AUTH-SRV LOGIN_SUCCESS user=admin src=10.20.4.15'

export default function Onboarding() {
  const [rawLog, setRawLog] = useState('')
  const [analysis, setAnalysis] = useState(null)
  const [fields, setFields] = useState([])
  const [parserName, setParserName] = useState('')
  const [created, setCreated] = useState(null)
  const [testLog, setTestLog] = useState('')
  const [testResult, setTestResult] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function handleAnalyze() {
    setError(null)
    setCreated(null)
    setBusy(true)
    try {
      const res = await api.analyzeUnknown(rawLog)
      setAnalysis(res)
      setFields(res.fields)
      setParserName('')
    } catch (e) {
      setError(e.message)
      setAnalysis(null)
    } finally {
      setBusy(false)
    }
  }

  function updateFieldValue(i, value) {
    setFields((prev) => prev.map((f, idx) => (idx === i ? { ...f, value } : f)))
  }

  function removeField(i) {
    setFields((prev) => prev.filter((_, idx) => idx !== i))
  }

  async function handleCreateParser() {
    if (!parserName.trim()) return
    setError(null)
    setBusy(true)
    try {
      const res = await api.createParser(rawLog, parserName.trim(), fields)
      setCreated(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  async function handleTest() {
    setError(null)
    setTestResult(null)
    setBusy(true)
    try {
      const res = await api.processLog(testLog)
      setTestResult(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-3 flex-wrap">
          <h1 className="text-xl font-semibold text-slate-100">Unknown source onboarding</h1>
          <span className="chip chip-success">Encrypted transmission</span>
        </div>
        <p className="text-sm text-mist mt-1 max-w-2xl">
          Teach ULPF how to understand a previously unseen log source. The system
          proposes a field mapping — you review and approve it before anything is saved.
        </p>
        <p className="text-xs text-mist mt-2">
          Sensitive onboarding payloads are encrypted in the browser with AES-256-GCM;
          the AES key is protected with the receiver's RSA-OAEP public key and decrypted
          only by the backend private key.
        </p>
      </div>

      {/* Step 1: sample input */}
      <div className="panel p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-sm font-medium text-slate-200">1. Paste a sample log</div>
          <button
            className="text-xs px-2.5 py-1 rounded-md bg-panel2 border border-line text-mist hover:text-slate-200"
            onClick={() => setRawLog(SAMPLE)}
          >
            Use unknown-source sample
          </button>
        </div>
        <textarea
          className="input mono h-20 resize-none"
          placeholder="Paste one line from the unrecognized source…"
          value={rawLog}
          onChange={(e) => setRawLog(e.target.value)}
        />
        <button className="btn-primary" onClick={handleAnalyze} disabled={busy || !rawLog.trim()}>
          {busy && !analysis ? 'Analyzing…' : 'Analyze'}
        </button>
      </div>

      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      {/* Step 2: AI suggestion */}
      {analysis && (
        <div className="panel p-4 space-y-3">
          <div className="flex items-center gap-2">
            <span className="chip chip-warning">ML / heuristic suggestion</span>
            <span className="text-xs text-mist">
              overall confidence {Math.round(analysis.overall_confidence * 100)}%
            </span>
          </div>
          <div className="text-sm font-medium text-slate-200">2. Suggested field mapping</div>
          <div className="space-y-2">
            {fields.map((f, i) => (
              <div key={i} className="flex items-center gap-3 bg-ink border border-line rounded-md px-3 py-2">
                <div className="w-32 text-xs text-mist shrink-0">{f.field}</div>
                <input
                  className="input flex-1 mono !py-1"
                  value={f.value || ''}
                  onChange={(e) => updateFieldValue(i, e.target.value)}
                />
                <span className="text-xs text-mist w-16 text-right">{Math.round(f.confidence * 100)}%</span>
                <span className="chip chip-neutral shrink-0">{f.source.replace('_', ' ')}</span>
                <button className="text-xs text-danger hover:underline" onClick={() => removeField(i)}>
                  Remove
                </button>
              </div>
            ))}
            {fields.length === 0 && <div className="text-xs text-mist">No fields left — analyze again.</div>}
          </div>
        </div>
      )}

      {/* Step 3: human approval -> create parser */}
      {analysis && fields.length > 0 && (
        <div className="panel p-4 space-y-3">
          <div className="flex items-center gap-2">
            <span className="chip chip-success">Human approval</span>
          </div>
          <div className="text-sm font-medium text-slate-200">3. Name and create the parser</div>
          <div className="flex items-center gap-3">
            <input
              className="input flex-1"
              placeholder="e.g. auth_server_v1"
              value={parserName}
              onChange={(e) => setParserName(e.target.value)}
            />
            <button className="btn-primary" onClick={handleCreateParser} disabled={busy || !parserName.trim()}>
              Accept and create parser
            </button>
          </div>
        </div>
      )}

      {/* Step 4: created confirmation + generated config */}
      {created && (
        <div className="panel p-4 space-y-3">
          <div className="flex items-center gap-2">
            <span className="chip chip-neutral">Parser created</span>
            <span className="mono text-sm text-slate-200">{created.parser.name}</span>
          </div>
          <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto max-h-56 text-slate-300">
{JSON.stringify(created.config, null, 2)}
          </pre>
        </div>
      )}

      {/* Step 5: test on a second log */}
      {created && (
        <div className="panel p-4 space-y-3">
          <div className="text-sm font-medium text-slate-200">4. Test the new parser on another log</div>
          <p className="text-xs text-mist">
            Paste a different sample from the same source — it should now be parsed
            automatically, with no further AI assistance needed.
          </p>
          <textarea
            className="input mono h-16 resize-none"
            placeholder="Paste a second log line from this source…"
            value={testLog}
            onChange={(e) => setTestLog(e.target.value)}
          />
          <button className="btn-secondary" onClick={handleTest} disabled={busy || !testLog.trim()}>
            Test new log
          </button>
          {testResult && (
            <div className="pt-2 space-y-2">
              <div className="flex items-center gap-2">
                <StatusChip value={testResult.status} />
                <span className="text-xs text-mist">
                  parsed by <span className="mono">{testResult.event?.parser_id?.slice(0, 8)}…</span>
                </span>
              </div>
              <pre className="mono text-xs bg-ink rounded-md p-3 overflow-auto max-h-56 text-slate-300">
{JSON.stringify(testResult.event?.event_data, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
