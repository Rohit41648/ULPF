import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../services/api.js'

export default function BlockchainPage() {
  const [status, setStatus] = useState(null)
  const [blocks, setBlocks] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch] = useState('')
  const [selectedBlock, setSelectedBlock] = useState(null)
  const [verifying, setVerifying] = useState(false)
  const [verificationResult, setVerificationResult] = useState(null)

  const [tamperedOnly, setTamperedOnly] = useState(false)

  function loadData() {
    setLoading(true)
    Promise.all([api.blockchainStatus(), api.blockchainBlocks()])
      .then(([statusData, blocksData]) => {
        setStatus(statusData)
        setBlocks(blocksData.blocks || [])
        setError(null)
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [])

  async function handleVerifyChain() {
    setVerifying(true)
    setVerificationResult(null)
    try {
      const res = await api.blockchainStatus()
      setStatus(res)
      if (res.valid) {
        setVerificationResult({
          valid: true,
          message: `Cryptographic chain validated across all ${res.blocks} blocks. Zero tampering detected.`,
        })
      } else {
        const list = (res.corrupted_blocks || []).map((idx) => `#${idx}`).join(', ')
        setVerificationResult({
          valid: false,
          corrupted: res.corrupted_blocks || [],
          errors: res.errors || [],
          message: `TAMPERING DETECTED in Block ${list || 'Unknown'}! Re-computed content hashes do not match stored cryptographic seals.`,
        })
      }
    } catch (e) {
      setVerificationResult({ valid: false, message: e.message })
    } finally {
      setVerifying(false)
    }
  }

  const filteredBlocks = blocks.filter((b) => {
    if (tamperedOnly && !status?.corrupted_blocks?.includes(b.index)) {
      return false
    }
    if (!search.trim()) return true
    const q = search.toLowerCase()
    return (
      String(b.index).includes(q) ||
      (b.event_id && b.event_id.toLowerCase().includes(q)) ||
      (b.hash && b.hash.toLowerCase().includes(q)) ||
      (b.block_hash && b.block_hash.toLowerCase().includes(q)) ||
      (b.previous_hash && b.previous_hash.toLowerCase().includes(q))
    )
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-slate-100">Blockchain Integrity Ledger</h1>
            <span className="chip chip-success">SHA-256 Hash Chain</span>
          </div>
          <p className="text-sm text-mist mt-1 max-w-2xl">
            Private cryptographic hash-chain securing every processed event. Each block links to
            the previous block's hash, providing mathematical proof of tamper-evident forensic traceability.
          </p>
        </div>
        <button
          onClick={handleVerifyChain}
          disabled={verifying}
          className="btn-primary flex items-center gap-2 text-xs shrink-0"
        >
          {verifying ? (
            'Verifying…'
          ) : (
            <>
              <span>🛡️</span>
              <span>Verify Chain Integrity</span>
            </>
          )}
        </button>
      </div>

      {verificationResult && (
        <div
          className={`panel p-4 border flex items-center justify-between text-xs font-medium ${
            verificationResult.valid
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'
              : 'border-red-500/40 bg-red-500/10 text-red-300'
          }`}
        >
          <div className="flex items-center gap-2">
            <span>{verificationResult.valid ? '✓' : '⚠'}</span>
            <span>{verificationResult.message}</span>
          </div>
          <button
            onClick={() => setVerificationResult(null)}
            className="text-mist hover:text-slate-200 ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {error && <div className="panel p-4 text-sm text-danger">{error}</div>}

      {/* Top Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="panel p-4">
          <div className="text-xs text-mist">Chain Status</div>
          <div className="flex items-center gap-2 mt-1">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                status?.valid ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'
              }`}
            />
            <div
              className={`text-lg font-bold ${
                status?.valid ? 'text-emerald-400' : 'text-red-400'
              }`}
            >
              {status?.valid ? 'VALID & INTACT' : 'COMPROMISED'}
            </div>
          </div>
          <div className="text-[10px] text-mist mt-1">
            {status?.valid
              ? 'Zero cryptographic breaks'
              : `${status?.corrupted_blocks?.length || 0} tampered block(s) detected`}
          </div>
        </div>

        <div className="panel p-4">
          <div className="text-xs text-mist">Total Blocks</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">{status?.blocks ?? '—'}</div>
          <div className="text-[10px] text-mist mt-1">Immutable ledger entries</div>
        </div>

        <div className="panel p-4">
          <div className="text-xs text-mist">Hash Algorithm</div>
          <div className="text-xl font-bold text-wire mt-1">SHA-256</div>
          <div className="text-[10px] text-mist mt-1">256-bit cryptographic digest</div>
        </div>

        <div className="panel p-4">
          <div className="text-xs text-mist">Storage Mode</div>
          <div className="text-xl font-bold text-slate-200 mt-1">Append-Only</div>
          <div className="text-[10px] text-mist mt-1">data/blockchain/ledger.json</div>
        </div>
      </div>

      {/* Block Explorer */}
      <div className="panel overflow-hidden">
        <div className="p-4 border-b border-line flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex flex-col sm:flex-row sm:items-center gap-4">
            <div>
              <div className="text-sm font-medium text-slate-200">Ledger Block Explorer</div>
              <div className="text-xs text-mist mt-0.5">
                Showing {filteredBlocks.length} of {blocks.length} cryptographic blocks
              </div>
            </div>

            {status?.corrupted_blocks?.length > 0 && (
              <div className="flex items-center gap-1.5 p-1 rounded-md bg-panel border border-line">
                <button
                  type="button"
                  onClick={() => setTamperedOnly(false)}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${
                    !tamperedOnly
                      ? 'bg-panel2 border border-wire text-wire font-medium'
                      : 'text-mist hover:text-slate-200'
                  }`}
                >
                  All ({blocks.length})
                </button>
                <button
                  type="button"
                  onClick={() => setTamperedOnly(true)}
                  className={`px-2.5 py-1 rounded text-xs transition-colors flex items-center gap-1.5 ${
                    tamperedOnly
                      ? 'bg-red-500/25 border border-red-500 text-red-200 font-bold'
                      : 'bg-red-500/10 border border-red-500/30 text-red-300 hover:bg-red-500/20'
                  }`}
                >
                  <span>🚨</span>
                  <span>Tampered ({status.corrupted_blocks.length})</span>
                </button>
              </div>
            )}
          </div>

          <input
            type="text"
            className="input text-xs mono w-full sm:w-72"
            placeholder="Search by block #, event ID, or hash…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs" style={{ minWidth: 900 }}>
            <thead>
              <tr className="text-left text-mist border-b border-line">
                <th className="px-4 py-2.5 font-normal w-24">Block #</th>
                <th className="px-4 py-2.5 font-normal whitespace-nowrap">Timestamp</th>
                <th className="px-4 py-2.5 font-normal whitespace-nowrap">Event ID</th>
                <th className="px-4 py-2.5 font-normal whitespace-nowrap">Block Hash (SHA-256)</th>
                <th className="px-4 py-2.5 font-normal whitespace-nowrap">Previous Hash</th>
                <th className="px-4 py-2.5 font-normal whitespace-nowrap text-right">Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredBlocks.map((b) => {
                const isGenesis = b.index === 0
                const isCorrupted = status?.corrupted_blocks?.includes(b.index)
                return (
                  <tr
                    key={b.index}
                    className={`border-b last:border-0 transition-colors ${
                      isCorrupted
                        ? 'bg-red-500/15 border-red-500/40 hover:bg-red-500/25'
                        : 'border-line/60 hover:bg-panel2/60'
                    }`}
                  >
                    <td className="px-4 py-3 font-semibold text-slate-200 mono">
                      <span className="flex items-center gap-1.5">
                        <span className={isCorrupted ? 'text-red-400 font-bold' : 'text-wire'}>
                          #{b.index}
                        </span>
                        {isGenesis && (
                          <span className="text-[9px] px-1.5 py-0.2 rounded bg-wire/15 text-wire uppercase">
                            Genesis
                          </span>
                        )}
                        {isCorrupted && (
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/30 text-red-200 font-bold border border-red-500/50 animate-pulse">
                            🚨 TAMPERED
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-mist mono whitespace-nowrap">
                      {new Date(b.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 mono whitespace-nowrap">
                      {b.event_id ? (
                        <Link
                          to={`/traceability?event=${b.event_id}`}
                          className="text-wire hover:underline"
                          title="View forensic trace"
                        >
                          {b.event_id.slice(0, 16)}…
                        </Link>
                      ) : (
                        <span className="text-mist">Genesis Block</span>
                      )}
                    </td>
                    <td className="px-4 py-3 mono text-slate-300">
                      <span className="block truncate max-w-xs" title={b.hash || b.block_hash}>
                        {(b.hash || b.block_hash) ? `${(b.hash || b.block_hash).slice(0, 20)}…` : '—'}
                      </span>
                    </td>
                    <td className="px-4 py-3 mono text-mist">
                      <span className="block truncate max-w-xs" title={b.previous_hash}>
                        {b.previous_hash === '0'
                          ? '0 (Initial Genesis)'
                          : `${b.previous_hash?.slice(0, 20)}…`}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => setSelectedBlock(b)}
                        className={`text-xs px-2.5 py-1 rounded border transition-colors ${
                          isCorrupted
                            ? 'bg-red-500/30 border-red-500 text-red-100 hover:bg-red-500/40 font-semibold shadow-sm'
                            : 'bg-panel2 border-line text-slate-300 hover:border-wire hover:text-slate-100'
                        }`}
                      >
                        {isCorrupted ? 'Inspect Breach' : 'Inspect'}
                      </button>
                    </td>
                  </tr>
                )
              })}
              {filteredBlocks.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-mist">
                    No matching blocks found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Block Inspection Modal */}
      {selectedBlock && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="panel max-w-xl w-full p-5 space-y-4 border border-line shadow-2xl">
            <div className="flex items-center justify-between border-b border-line pb-3">
              <div className="flex items-center gap-2">
                <span className="text-wire font-bold">Block #{selectedBlock.index}</span>
                <span className="text-xs text-mist">Cryptographic Proof Details</span>
              </div>
              <button
                onClick={() => setSelectedBlock(null)}
                className="text-mist hover:text-slate-100 text-lg"
              >
                ✕
              </button>
            </div>

            {/* If block is corrupted, show prominent forensic breach breakdown */}
            {status?.errors?.filter((e) => e.index === selectedBlock.index).map((err, i) => (
              <div
                key={i}
                className="p-3.5 rounded-lg bg-red-500/15 border border-red-500/40 text-red-200 space-y-2 text-xs"
              >
                <div className="font-semibold flex items-center gap-2 text-sm text-red-300">
                  <span>🚨</span>
                  <span>Cryptographic Seal Invalidated</span>
                </div>
                <p className="text-red-200 leading-relaxed text-[11px]">
                  {err.message}
                </p>
                {err.calculated_hash && (
                  <div className="space-y-1.5 pt-1 text-[11px] font-mono">
                    <div>
                      <span className="text-mist block">Re-computed Hash from Block Content:</span>
                      <span className="text-red-300 break-all select-all font-bold block bg-black/40 p-1.5 rounded border border-red-500/30">
                        {err.calculated_hash}
                      </span>
                    </div>
                    <div>
                      <span className="text-mist block">Stored Seal in Block:</span>
                      <span className="text-slate-400 break-all select-all line-through block bg-black/40 p-1.5 rounded border border-line">
                        {err.stored_hash}
                      </span>
                    </div>
                  </div>
                )}
              </div>
            ))}

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-mist block mb-0.5">Block Hash (SHA-256):</span>
                <div className="p-2 bg-ink rounded mono text-slate-200 select-all break-all border border-line">
                  {selectedBlock.hash || selectedBlock.block_hash}
                </div>
              </div>

              <div>
                <span className="text-mist block mb-0.5">Previous Block Hash:</span>
                <div className="p-2 bg-ink rounded mono text-slate-300 select-all break-all border border-line">
                  {selectedBlock.previous_hash}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="text-mist block mb-0.5">Event Hash:</span>
                  <div className="p-2 bg-ink rounded mono text-slate-300 select-all break-all border border-line">
                    {selectedBlock.event_hash || 'None (Genesis)'}
                  </div>
                </div>
                <div>
                  <span className="text-mist block mb-0.5">Raw Log Hash:</span>
                  <div className="p-2 bg-ink rounded mono text-slate-300 select-all break-all border border-line">
                    {selectedBlock.raw_log_hash || 'None (Genesis)'}
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-1">
                <div>
                  <span className="text-mist">Timestamp:</span>{' '}
                  <span className="mono text-slate-200">
                    {new Date(selectedBlock.timestamp).toLocaleString()}
                  </span>
                </div>
                <div>
                  <span className="text-mist">Parser Used:</span>{' '}
                  <span className="mono text-slate-200">
                    {selectedBlock.parser_id || 'genesis'}
                  </span>
                </div>
              </div>
            </div>

            <div className="flex justify-between items-center pt-3 border-t border-line">
              {selectedBlock.event_id ? (
                <Link
                  to={`/traceability?event=${selectedBlock.event_id}`}
                  className="text-wire hover:underline text-xs"
                >
                  View Full Forensic Trace →
                </Link>
              ) : (
                <span />
              )}
              <button
                type="button"
                className="btn-secondary !py-1 !px-3 text-xs"
                onClick={() => setSelectedBlock(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
