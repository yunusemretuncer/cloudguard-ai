const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-900/40 text-red-300 border-red-700',
  HIGH: 'bg-orange-900/40 text-orange-300 border-orange-700',
  MEDIUM: 'bg-yellow-900/40 text-yellow-300 border-yellow-700',
  LOW: 'bg-blue-900/40 text-blue-300 border-blue-700',
}

const formatTime = (iso) => {
  const date = new Date(iso)
  const now = new Date()
  const diffMin = Math.floor((now - date) / 60000)
  if (diffMin < 1) return 'az önce'
  if (diffMin < 60) return `${diffMin} dk önce`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr} sa önce`
  return date.toLocaleDateString('tr-TR')
}

function AlertPanel({ alerts }) {
  if (alerts.length === 0) {
    return (
      <div className="text-center text-slate-500 py-8 text-sm">
        Henüz alert yok. Agent'a bir güvenlik sorusu sorduğunuzda burada görünecekler.
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {alerts.map((alert) => (
        <div
          key={alert.id}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-3 hover:border-slate-600 transition"
        >
          <div className="flex items-start justify-between mb-2">
            <span
              className={`text-xs font-mono px-2 py-0.5 rounded border ${
                SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.LOW
              }`}
            >
              {alert.severity}
            </span>
            <span className="text-xs text-slate-500">{formatTime(alert.created_at)}</span>
          </div>

          <div className="text-sm font-medium text-slate-200 mb-1">{alert.title}</div>
          <div className="text-xs text-slate-400 leading-relaxed mb-2">{alert.detail}</div>

          <div className="flex flex-wrap gap-2 text-xs text-slate-500">
            {alert.mitre_technique && (
              <span className="font-mono">MITRE: {alert.mitre_technique}</span>
            )}
            {alert.source_ip && (
              <span className="font-mono">IP: {alert.source_ip}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

export default AlertPanel