/**
 * Tek bir mesaj baloncuğu — kullanıcı veya agent.
 *
 * Props:
 *   role: 'user' | 'agent'
 *   content: string
 *   timestamp?: string (ISO date)
 */
function MessageBubble({ role, content, timestamp }) {
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
        </div>
      </div>
    </div>
  )
}

export default MessageBubble