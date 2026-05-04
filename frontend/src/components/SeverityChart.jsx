import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626', // red-600
  HIGH: '#ea580c',     // orange-600
  MEDIUM: '#ca8a04',   // yellow-600
  LOW: '#2563eb',      // blue-600
}

function SeverityChart({ counts }) {
  // counts: { CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 1 }
  const data = Object.entries(counts)
    .filter(([, value]) => value > 0)
    .map(([name, value]) => ({ name, value }))

  const total = data.reduce((sum, d) => sum + d.value, 0)

  if (total === 0) {
    return (
      <div className="h-40 flex items-center justify-center text-sm text-slate-500">
        Veri yok
      </div>
    )
  }

  return (
    <div className="relative h-40">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={45}
            outerRadius={65}
            paddingAngle={2}
            dataKey="value"
          >
            {data.map((entry) => (
              <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '6px',
              fontSize: '12px',
            }}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Merkez sayı */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="text-2xl font-bold text-slate-100">{total}</div>
        <div className="text-xs text-slate-500">Toplam</div>
      </div>
    </div>
  )
}

export default SeverityChart