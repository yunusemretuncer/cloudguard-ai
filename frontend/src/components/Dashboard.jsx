import { useState, useEffect } from 'react'
import ChatInterface from './ChatInterface'
import AlertPanel from './AlertPanel'
import SeverityChart from './SeverityChart'
import ToolActivity from './ToolActivity'
import { api } from '../services/api'
import { MOCK_ALERTS, MOCK_SEVERITY_COUNTS } from '../services/mockData'

// Tool'lar bağlanmadığı için backend boş döner — UI'da bir şey görmek için
// mock'a düşüyoruz. Tool entegrasyonundan sonra USE_MOCK_DATA = false olacak.
const USE_MOCK_DATA = true

function Dashboard() {
  const [alerts, setAlerts] = useState([])
  const [severityCounts, setSeverityCounts] = useState({
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
  })
  const [toolActivities] = useState([])  // tool entegrasyonunda dolacak

  useEffect(() => {
    if (USE_MOCK_DATA) {
      setAlerts(MOCK_ALERTS)
      setSeverityCounts(MOCK_SEVERITY_COUNTS)
      return
    }
    // Gerçek API
    api.alerts()
      .then((data) => {
        setAlerts(data.items)
        setSeverityCounts(data.severity_counts)
      })
      .catch((err) => {
        console.error('Alert fetch failed:', err)
      })
  }, [])

  return (
    <div className="h-screen w-screen flex bg-slate-950">
      {/* Sol: Chat */}
      <div className="flex-1 min-w-0 border-r border-slate-800">
        <ChatInterface />
      </div>

      {/* Sağ: Panel */}
      <aside className="w-96 flex flex-col bg-slate-900 overflow-y-auto">
        {/* Severity chart */}
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

        {/* Alerts */}
        <section className="p-4 border-b border-slate-800 flex-1">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Son Alert'ler
            </h2>
            <span className="text-xs text-slate-600">{alerts.length}</span>
          </div>
          <AlertPanel alerts={alerts} />
        </section>

        {/* Tool activity */}
        <section className="p-4">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
            Tool Aktivitesi
          </h2>
          <ToolActivity activities={toolActivities} />
        </section>
      </aside>
    </div>
  )
}

export default Dashboard