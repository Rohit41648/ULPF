import React, { useState } from 'react'

const DEFAULT_KNOWN_FIELDS = {
  cisco_syslog_v1: {
    timestamp: '%b %d %H:%M:%S',
    hostname: 'host',
    protocol: 'proto',
    source_ip: 'src_ip',
    source_port: 'src_port',
    destination_ip: 'dst_ip',
    destination_port: 'dst_port',
    event_action: 'Built|Deny',
  },
  fortigate_kv_v1: {
    timestamp: 'date=... time=...',
    hostname: 'devname',
    source_ip: 'srcip',
    destination_ip: 'dstip',
    destination_port: 'dstport',
    protocol: 'proto',
    event_action: 'action',
  },
  linux_syslog_v1: {
    timestamp: '%b %d %H:%M:%S',
    hostname: 'host',
    username: 'user',
    source_ip: 'from <ip>',
    event_action: 'Accepted|Failed',
  },
  windows_json_v1: {
    timestamp: 'TimeCreated',
    hostname: 'Computer',
    username: 'User',
    source_ip: 'IpAddress',
    event_action: 'EventID',
  },
  apache_access_v1: {
    timestamp: '%d/%b/%Y:%H:%M:%S',
    source_ip: 'client_ip',
    http_method: 'method',
    http_path: 'path',
    http_status_code: 'status',
    http_user_agent: 'agent',
    ext_response_size: 'size',
  },
}

export default function EditParserModal({ parser, busy, onSave, onClose }) {
  const [name, setName] = useState(parser.name || '')
  const [status, setStatus] = useState(parser.status || 'active')

  // Initialize field list from parser.config.fields or fallback defaults
  const [fieldList, setFieldList] = useState(() => {
    let sourceFields = parser.config?.fields
    if (!sourceFields || Object.keys(sourceFields).length === 0) {
      sourceFields = DEFAULT_KNOWN_FIELDS[parser.name] || {}
    }
    return Object.entries(sourceFields).map(([k, v], idx) => ({
      id: `field_${idx}_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      key: k,
      value: typeof v === 'object' ? JSON.stringify(v) : String(v || ''),
    }))
  })

  // Quick-add state
  const [newKey, setNewKey] = useState('')
  const [newVal, setNewVal] = useState('')

  function handleFieldKeyChange(id, key) {
    setFieldList((prev) =>
      prev.map((item) => (item.id === id ? { ...item, key } : item))
    )
  }

  function handleFieldValueChange(id, value) {
    setFieldList((prev) =>
      prev.map((item) => (item.id === id ? { ...item, value } : item))
    )
  }

  function handleRemoveField(id) {
    setFieldList((prev) => prev.filter((item) => item.id !== id))
  }

  function handleAddNewField() {
    if (!newKey.trim()) return
    const id = `field_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`
    setFieldList((prev) => [
      ...prev,
      { id, key: newKey.trim(), value: newVal.trim() },
    ])
    setNewKey('')
    setNewVal('')
  }

  function handleAddBlankRow() {
    const id = `field_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`
    setFieldList((prev) => [...prev, { id, key: '', value: '' }])
  }

  function handleSubmit(e) {
    e.preventDefault()
    if (!name.trim()) return

    const finalFields = {}
    fieldList.forEach((item) => {
      const k = item.key.trim()
      if (k) {
        finalFields[k] = item.value
      }
    })

    const existingDetails = parser.config?.field_details || []
    const detailsMap = new Map(existingDetails.map((d) => [d.field, d]))
    const finalDetails = Object.entries(finalFields).map(([k, v]) => {
      if (detailsMap.has(k)) {
        return { ...detailsMap.get(k), field: k, value: v, raw_token: v }
      }
      return {
        field: k,
        value: v,
        mapped_to: k,
        confidence: 1.0,
        source: 'manual_mapping',
        data_type: 'string',
        status: 'custom',
        raw_token: v,
      }
    })

    const payload = {
      name: name.trim(),
      status,
      config: {
        ...(parser.config || {}),
        parser_name: name.trim(),
        format: parser.format || parser.config?.format || 'custom',
        fields: finalFields,
        field_details: finalDetails,
      },
    }

    onSave(payload)
  }

  const isDeterministic =
    parser.source_type !== 'ai_generated' && parser.source_type !== 'ml_generated'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="panel max-w-xl w-full p-5 space-y-4 border border-line shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-line pb-3">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base font-semibold text-slate-100">Edit Parser</h3>
              <span
                className={`chip text-[10px] ${
                  isDeterministic ? 'chip-neutral' : 'chip-warning'
                }`}
              >
                {isDeterministic ? 'Deterministic (Known)' : 'Offline ML / Custom (Unknown)'}
              </span>
            </div>
            <p className="text-xs text-mist mt-0.5">
              Modify parser configuration, name, active status, or field extraction rules.
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-mist hover:text-slate-100 text-lg transition-colors"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Parser Name */}
          <div>
            <label className="block text-xs font-medium text-mist mb-1">
              Parser Name
            </label>
            <input
              type="text"
              className="input w-full mono text-sm"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. auth_service_v1"
              required
            />
          </div>

          {/* Status */}
          <div>
            <label className="block text-xs font-medium text-mist mb-1">Status</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="radio"
                  name="status"
                  value="active"
                  checked={status === 'active'}
                  onChange={(e) => setStatus(e.target.value)}
                  className="accent-wire"
                />
                Active (processes incoming logs)
              </label>
              <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="radio"
                  name="status"
                  value="disabled"
                  checked={status === 'disabled'}
                  onChange={(e) => setStatus(e.target.value)}
                  className="accent-wire"
                />
                Disabled (bypassed during detection)
              </label>
            </div>
          </div>

          {/* Field Mappings: Add, Delete, and Edit */}
          <div className="space-y-2 pt-2 border-t border-line">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <label className="block text-xs font-medium text-mist">
                  Field Mappings ({fieldList.length})
                </label>
                <span className="text-[10px] text-mist/70">
                  (Edit field names and mapping patterns)
                </span>
              </div>
              <button
                type="button"
                onClick={handleAddBlankRow}
                className="text-xs px-2 py-0.5 rounded bg-wire/10 border border-wire/30 text-wire hover:bg-wire/20 transition-colors"
                title="Add a new blank field row"
              >
                + Add Field
              </button>
            </div>

            {/* Scrollable list of fields */}
            <div className="max-h-56 overflow-y-auto space-y-2 pr-1">
              {fieldList.map((item) => (
                <div
                  key={item.id}
                  className="flex items-center gap-2 bg-ink/50 p-2 rounded border border-line text-xs hover:border-line/80 transition-colors"
                >
                  <input
                    type="text"
                    className="input mono !py-1 text-xs w-32 shrink-0 text-wire font-medium bg-ink"
                    value={item.key}
                    onChange={(e) => handleFieldKeyChange(item.id, e.target.value)}
                    placeholder="field_name"
                    title="Field Name (Key)"
                  />
                  <span className="text-mist text-xs">→</span>
                  <input
                    type="text"
                    className="input flex-1 mono !py-1 text-xs text-slate-200"
                    value={item.value}
                    onChange={(e) => handleFieldValueChange(item.id, e.target.value)}
                    placeholder="token match rule, pattern, or example value"
                    title="Token match pattern or example value"
                  />
                  <button
                    type="button"
                    onClick={() => handleRemoveField(item.id)}
                    className="text-red-400 hover:text-red-300 px-1.5 py-0.5 rounded hover:bg-red-500/10 text-sm transition-colors"
                    title="Remove field"
                  >
                    ✕
                  </button>
                </div>
              ))}

              {fieldList.length === 0 && (
                <div className="text-center py-4 text-xs text-mist border border-dashed border-line/60 rounded bg-ink/20">
                  No field mappings defined yet. Click "+ Add Field" below to add one.
                </div>
              )}
            </div>

            {/* Quick Add Bar */}
            <div className="flex items-center gap-2 pt-2 border-t border-line/40">
              <input
                type="text"
                className="input mono !py-1 text-xs w-32 shrink-0 text-wire placeholder:text-mist/50"
                placeholder="New field name"
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    handleAddNewField()
                  }
                }}
              />
              <span className="text-mist text-xs">→</span>
              <input
                type="text"
                className="input flex-1 mono !py-1 text-xs text-slate-200 placeholder:text-mist/50"
                placeholder="Mapping pattern / token rule"
                value={newVal}
                onChange={(e) => setNewVal(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    handleAddNewField()
                  }
                }}
              />
              <button
                type="button"
                onClick={handleAddNewField}
                disabled={!newKey.trim()}
                className="text-xs px-2.5 py-1 rounded bg-wire/15 border border-wire/40 text-wire hover:bg-wire/25 transition-colors disabled:opacity-40 whitespace-nowrap"
              >
                + Add
              </button>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex justify-end gap-2 pt-3 border-t border-line">
            <button
              type="button"
              className="btn-secondary !py-1.5 !px-3 text-xs"
              onClick={onClose}
              disabled={busy}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary !py-1.5 !px-4 text-xs font-medium"
              disabled={busy || !name.trim()}
            >
              {busy ? 'Saving…' : 'Save Changes'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
