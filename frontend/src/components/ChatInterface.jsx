import { useState, useRef, useEffect } from 'react'
import { api, ApiError } from '../services/api'
import MessageBubble from './MessageBubble'

// Sayfa yüklendiğinde rastgele bir thread_id üret — her tarayıcı sekmesi
// kendi konuşmasına sahip olsun. İleride kullanıcı bazlı yapılır.
const generateThreadId = () => `web-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

function ChatInterface({ onToolUse }) {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)
  const [threadId] = useState(generateThreadId)

  const messagesEndRef = useRef(null)
  const inputRef = useRef(null)

  // Yeni mesaj geldikçe en alta kaydır
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, isLoading])

  // Sayfa yüklendiğinde input'a odaklan
  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const sendMessage = async () => {
    const trimmed = input.trim()
    if (!trimmed || isLoading) return

    const userMessage = {
      role: 'user',
      content: trimmed,
      timestamp: new Date().toISOString(),
    }

    setMessages((prev) => [...prev, userMessage])
    setInput('')
    setIsLoading(true)
    setError(null)

    try {
      const data = await api.chat(trimmed, threadId)
      const agentMessage = {
        role: 'agent',
        content: data.reply,
        timestamp: new Date().toISOString(),
        toolCalls: data.tool_calls || [],
      }
      setMessages((prev) => [...prev, agentMessage])

      if (onToolUse && data.tool_calls?.length > 0) {
        onToolUse(data.tool_calls)
      }
      
    } catch (err) {
      const errMsg =
        err instanceof ApiError
          ? `Backend hatası (${err.status}): ${err.message}`
          : `Bağlantı hatası: ${err.message}`
      setError(errMsg)
    } finally {
      setIsLoading(false)
      inputRef.current?.focus()
    }
  }

  const handleKeyDown = (e) => {
    // Enter gönderir, Shift+Enter yeni satır
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  return (
    <div className="flex flex-col h-full bg-slate-900">
      {/* Header */}
      <div className="border-b border-slate-800 px-6 py-4 bg-slate-900/95 backdrop-blur">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold text-slate-100">CloudGuard AI</h1>
            <p className="text-xs text-slate-500">Cloud Security Monitoring Agent</p>
          </div>
          <div className="text-xs text-slate-500 font-mono">
            thread: {threadId.slice(0, 16)}…
          </div>
        </div>
      </div>

      {/* Mesaj listesi */}
      <div className="flex-1 overflow-y-auto px-6 py-4">
        {messages.length === 0 && (
          <div className="text-center text-slate-500 mt-12">
            <p className="text-sm mb-2">Bir güvenlik sorusu sorarak başlayın</p>
            <p className="text-xs opacity-70">
              Örnek: "Son 24 saatte başarısız login denemeleri var mı?"
            </p>
          </div>
        )}

        {messages.map((msg, idx) => (
          <MessageBubble
            key={idx}
            role={msg.role}
            content={msg.content}
            timestamp={msg.timestamp}
            toolCalls={msg.toolCalls}
          />
        ))}

        {isLoading && (
          <div className="flex justify-start mb-3">
            <div className="bg-slate-800 border border-slate-700 rounded-2xl rounded-tl-sm px-4 py-3">
              <div className="flex gap-1">
                <span className="w-2 h-2 bg-slate-500 rounded-full animate-bounce [animation-delay:-0.3s]"></span>
                <span className="w-2 h-2 bg-slate-500 rounded-full animate-bounce [animation-delay:-0.15s]"></span>
                <span className="w-2 h-2 bg-slate-500 rounded-full animate-bounce"></span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Hata mesajı */}
      {error && (
        <div className="px-6 py-2 bg-red-900/30 border-t border-red-900 text-red-300 text-sm">
          ⚠ {error}
        </div>
      )}

      {/* Input */}
      <div className="border-t border-slate-800 p-4 bg-slate-900">
        <div className="flex gap-2 items-end">
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Bir güvenlik sorusu sorun..."
            rows={1}
            className="flex-1 bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-blue-500 resize-none"
            disabled={isLoading}
          />
          <button
            onClick={sendMessage}
            disabled={isLoading || !input.trim()}
            className="bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 text-white rounded-xl px-5 py-3 text-sm font-medium transition"
          >
            Gönder
          </button>
        </div>
        <p className="text-xs text-slate-600 mt-2">
          Enter: gönder · Shift+Enter: yeni satır
        </p>
      </div>
    </div>
  )
}

export default ChatInterface