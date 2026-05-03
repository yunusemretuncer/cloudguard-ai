function ToolActivity({ activities }) {
  if (!activities || activities.length === 0) {
    return (
      <div className="text-center text-slate-500 py-6 text-sm">
        <div className="text-3xl mb-2 opacity-30">⚙</div>
        <p className="text-xs">Henüz tool kullanılmadı</p>
        <p className="text-xs opacity-70 mt-1">
          Agent araç çağırdığında burada listelenecek
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {activities.map((act, idx) => (
        <div
          key={idx}
          className="bg-slate-800/50 border border-slate-700 rounded-lg p-2 text-xs"
        >
          <div className="flex justify-between items-center">
            <span className="font-mono text-blue-400">{act.tool_name}</span>
            <span className="text-slate-500">
              {new Date(act.timestamp).toLocaleTimeString('tr-TR', {
                hour: '2-digit',
                minute: '2-digit',
              })}
            </span>
          </div>
          {act.input && (
            <div className="text-slate-400 mt-1 truncate">{act.input}</div>
          )}
        </div>
      ))}
    </div>
  )
}

export default ToolActivity