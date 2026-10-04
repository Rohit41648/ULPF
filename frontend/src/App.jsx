import React from 'react'
import { NavLink, Route, Routes } from 'react-router-dom'
import Overview from './pages/Overview.jsx'
import LogAnalyzer from './pages/LogAnalyzer.jsx'
import EventsPage from './pages/EventsPage.jsx'
import ParserRegistry from './pages/ParserRegistry.jsx'
import Traceability from './pages/Traceability.jsx'
import BlockchainPage from './pages/BlockchainPage.jsx'

const NAV_ITEMS = [
  { to: '/', label: 'Overview', end: true },
  { to: '/analyzer', label: 'Log Analyzer' },
  { to: '/events', label: 'Events' },
  { to: '/parsers', label: 'Parser Registry' },
  { to: '/traceability', label: 'Traceability' },
  { to: '/blockchain', label: 'Blockchain Ledger' },
]

export default function App() {
  return (
    <div className="flex h-screen">
      <aside className="w-64 shrink-0 bg-panel border-r border-line flex flex-col">
        <div className="px-5 py-5 border-b border-line">
          <div className="text-[15px] font-semibold text-slate-100">ULPF</div>
          <div className="text-xs text-mist mt-0.5 leading-snug">
            Universal Log Pre-processing Framework
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-0.5">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `block px-3 py-2 rounded-md text-sm transition-colors ${isActive
                  ? 'bg-wire/15 text-wire font-medium'
                  : 'text-mist hover:text-slate-200 hover:bg-panel2'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-5 py-4 border-t border-line text-xs text-mist flex items-center justify-between">
          <span>Engine: <strong className="text-emerald-400">Offline ML</strong></span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" title="System Online" />
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="max-w-6xl mx-auto px-8 py-8">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/analyzer" element={<LogAnalyzer />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/parsers" element={<ParserRegistry />} />
            <Route path="/traceability" element={<Traceability />} />
            <Route path="/blockchain" element={<BlockchainPage />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}


