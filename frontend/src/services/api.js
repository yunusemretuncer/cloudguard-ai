/**
 * Backend API service layer.
 * Tüm /api/* çağrıları Vite proxy üzerinden localhost:8000'e iletilir.
 */

const API_BASE = '/api'

class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })

  if (!response.ok) {
    let detail = response.statusText
    try {
      const errorData = await response.json()
      detail = errorData.detail || detail
    } catch {
      // JSON değilse statusText kullan
    }
    throw new ApiError(detail, response.status)
  }

  return response.json()
}

export const api = {
  /** Agent'a mesaj gönder, cevabı al. */
  chat: (message, threadId = 'default') =>
    request('/chat', {
      method: 'POST',
      body: JSON.stringify({ message, thread_id: threadId }),
    }),

  /** Konuşma geçmişini çek. */
  history: (threadId = null, limit = 50) => {
    const params = new URLSearchParams({ limit: String(limit) })
    if (threadId) params.append('thread_id', threadId)
    return request(`/history?${params.toString()}`)
  },

  /** Backend sağlık kontrolü. */
  health: () => request('/health'),

  /** Alert listesi. */
  alerts: (severity = null, limit = 50) => {
    const params = new URLSearchParams({ limit: String(limit) })
    if (severity) params.append('severity', severity)
    return request(`/alerts?${params.toString()}`)
  },
}

export { ApiError }

