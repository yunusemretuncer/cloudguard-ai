/**
 * Tek bir mesaj baloncuğu — kullanıcı veya agent.
 *
 * Props:
 *   role: 'user' | 'agent'
 *   content: string
 *   timestamp?: string (ISO date)
 */
function MessageBubble({ role, content, timestamp, toolCalls = [] }) {
  const isUser = role === 'user'

  return (
    <div className={`flex ${isUser ? 'justify-end' : 'justify-start'} mb-3`}>
      <div className={`max-w-[80%] ${isUser ? 'order-2' : 'order-1'}`}>
        <div className={`text-xs text-slate-500 mb-1 ${isUser ? 'text-right' : 'text-left'}`}>
          {isUser ? 'Sen' : 'CloudGuard AI'}
          {timestamp && (
            <span className="ml-2 opacity-60">
              {new Date(timestamp).toLocaleTimeString('tr-TR', {
                hour: '2-digit',
                minute: '2-digit',
              })}
            </span>
          )}
        </div>
        <div
          className={`rounded-2xl px-4 py-3 ${
            isUser
              ? 'bg-blue-600 text-white rounded-tr-sm'
              : 'bg-slate-800 text-slate-100 rounded-tl-sm border border-slate-700'
          }`}
        >
          <div className="whitespace-pre-wrap break-words text-sm leading-relaxed">
            {content}
          </div>

          {/* Tool kullanım rozeti — sadece agent mesajlarında */}
          {!isUser && toolCalls.length > 0 && (
            <div className="mt-2 pt-2 border-t border-slate-700/50 flex flex-wrap gap-1">
              {toolCalls.map((tc, idx) => (
                <span
                  key={idx}
                  className="text-xs font-mono bg-blue-900/40 text-blue-300 border border-blue-800 rounded px-2 py-0.5"
                >
                  ⚙ {tc.name}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default MessageBubble

