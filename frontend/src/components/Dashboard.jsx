import { useState, useEffect } from 'react'
import ChatInterface from './ChatInterface'
import AlertPanel from './AlertPanel'
import SeverityChart from './SeverityChart'
import ToolActivity from './ToolActivity'
import { api } from '../services/api'
import { MOCK_ALERTS, MOCK_SEVERITY_COUNTS } from '../services/mockData'

const USE_MOCK_DATA = true
const MAX_TOOL_HISTORY = 20  // panelde son 20 çağrıyı tut

function Dashboard() {
  const [alerts, setAlerts] = useState([])
  const [severityCounts, setSeverityCounts] = useState({
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0,
  })
  const [toolActivities, setToolActivities] = useState([])

  useEffect(() => {
    if (USE_MOCK_DATA) {
      setAlerts(MOCK_ALERTS)
      setSeverityCounts(MOCK_SEVERITY_COUNTS)
      return
    }
    api.alerts().then((data) => {
      setAlerts(data.items)
      setSeverityCounts(data.severity_counts)
    }).catch((err) => console.error('Alert fetch failed:', err))
  }, [])

  // Tool kullanımı geldikçe listenin başına ekle
  const handleToolUse = (toolCalls) => {
    const newActivities = toolCalls.map((tc) => ({
      tool_name: tc.name,
      input: formatArgs(tc.args),
      timestamp: new Date().toISOString(),
    }))

    setToolActivities((prev) =>
      [...newActivities, ...prev].slice(0, MAX_TOOL_HISTORY)
    )
  }

  return (
    <div className="h-screen w-screen flex bg-slate-950">
      <div className="flex-1 min-w-0 border-r border-slate-800">
        <ChatInterface onToolUse={handleToolUse} />
      </div>

      <aside className="w-96 flex flex-col bg-slate-900 overflow-y-auto">
        <section className="p-4 border-b border-slate-800">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
            Severity Dağılımı
          </h2>
          <SeverityChart counts={severityCounts} />
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
            {Object.entries(severityCounts).map(([sev, count]) => (
              <div key={sev} className="flex justify-between bg-slate-800/40 rounded px-2 py-1">
                <span className="text-slate-400">{sev}</span>
                <span className="font-mono text-slate-200">{count}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="p-4 border-b border-slate-800">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Son Alert'ler
            </h2>
            <span className="text-xs text-slate-600">{alerts.length}</span>
          </div>
          <AlertPanel alerts={alerts} />
        </section>

        <section className="p-4 flex-shrink-0">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Tool Aktivitesi
            </h2>
            <span className="text-xs text-slate-600">{toolActivities.length}</span>
          </div>
          <ToolActivity activities={toolActivities} />
        </section>
      </aside>
    </div>
  )
}

// Tool args'larını okunabilir tek satıra formatla
function formatArgs(args) {
  if (!args || Object.keys(args).length === 0) return ''
  const entries = Object.entries(args).map(([k, v]) => {
    const val = typeof v === 'string' ? v : JSON.stringify(v)
    return `${k}: ${val.length > 30 ? val.slice(0, 30) + '…' : val}`
  })
  return entries.join(', ')
}

export default Dashboard