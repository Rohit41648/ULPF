import React from 'react'

const STYLES = {
  SUCCESS: 'chip-success',
  WARNING: 'chip-warning',
  FAILED: 'chip-danger',
  UNKNOWN_FORMAT: 'chip-neutral',
  low: 'chip-success',
  medium: 'chip-warning',
  high: 'chip-danger',
  critical: 'chip-danger',
}

export default function StatusChip({ value }) {
  if (!value) return <span className="chip chip-neutral">unknown</span>
  const cls = STYLES[value] || 'chip-neutral'
  return <span className={`chip ${cls}`}>{value.toLowerCase()}</span>
}
