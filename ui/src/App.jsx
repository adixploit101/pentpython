import { useState, useRef, useEffect } from 'react'
import './App.css'

const API_URL = ''

function App() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState('Connecting...')
  const messagesEndRef = useRef(null)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  useEffect(() => {
    fetch(`${API_URL}/health`)
      .then(res => res.json())
      .then(data => setStatus(`Active • ${data.agent_type}`))
      .catch(() => setStatus('Offline'))
  }, [])

  const sendMessage = async () => {
    if (!input.trim() || loading) return

    const userMessage = input
    setInput('')
    setMessages(prev => [...prev, { type: 'user', content: userMessage }])
    setLoading(true)

    try {
      const response = await fetch(`${API_URL}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMessage })
      })

      const data = await response.json()
      setMessages(prev => [...prev, { type: 'assistant', content: data.response }])
    } catch (error) {
      setMessages(prev => [...prev, {
        type: 'error',
        content: 'Connection failed. Make sure the backend is running:\npython server.py'
      }])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const quickActions = [
    { icon: '🔍', text: 'Scan a website', action: 'Do a security scan of ' },
    { icon: '🔐', text: 'Check SSL', action: 'Check SSL certificate for ' },
    { icon: '🌐', text: 'DNS Lookup', action: 'Do a DNS lookup for ' },
    { icon: '🛡️', text: 'Full Audit', action: 'Do a complete security audit of ' },
  ]

  const hasMessages = messages.length > 0

  const extractPdfFilename = (text) => {
    if (typeof text !== 'string') return null
    // Extremely liberal regex: just look for anything that looks like our report filenames
    const match = text.match(/(report_[\w.-]+\.pdf)/i)
    return match ? match[1] : null
  }




  return (
    <div className={`app ${hasMessages ? 'chat-mode' : ''}`}>
      <header className="header">
        <div className="header-left">
          <svg className="menu-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="7" height="7" rx="1" />
            <rect x="14" y="3" width="7" height="7" rx="1" />
            <rect x="3" y="14" width="7" height="7" rx="1" />
            <rect x="14" y="14" width="7" height="7" rx="1" />
          </svg>
        </div>
        <div className="status-badge">
          <span className="status-dot"></span>
          {status}
        </div>
      </header>

      <main className="main-content">
        <div className="logo-container">🛡️</div>

        <div className="greeting">
          <h1>Good to See You!<br />How Can I <span>Assist</span>?</h1>
          <p>Your AI-powered security assistant, ready 24/7</p>
        </div>

        {hasMessages && (
          <div className="messages-container">
            {messages.map((msg, idx) => {
              const pdfFile = msg.type === 'assistant' ? extractPdfFilename(msg.content) : null

              return (
                <div key={idx} className={`message ${msg.type}`}>
                  <div className="message-label">
                    {msg.type === 'user' ? '👤 You' : msg.type === 'error' ? '⚠️ Error' : '🤖 PentAgent'}
                  </div>
                  <div className="message-content" style={{ whiteSpace: 'pre-wrap' }}>
                    {msg.content}
                  </div>
                  {pdfFile && (
                    <div className="message-actions">
                      <a
                        href={`${API_URL}/download/${pdfFile}`}
                        className="download-btn"
                        target="_blank"
                        rel="noopener noreferrer"
                        download={pdfFile}
                      >
                        <span className="icon">📥</span>
                        Download PDF Report
                      </a>
                    </div>
                  )}
                </div>
              )
            })}
            {loading && (
              <div className="loading">
                <div className="loading-dots">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
                <span>Analyzing...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        )}

        <div className="input-container">
          <div className="input-header">
            <div className="pro-badge">⚡ PentPython Security Console</div>
            <div className="active-indicator">Active</div>
          </div>
          <div className="input-wrapper">
            <span className="plus-icon">+</span>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask anything about security..."
              disabled={loading}
            />
            <button className="send-btn" onClick={sendMessage} disabled={loading || !input.trim()}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M22 2L11 13M22 2L15 22L11 13M22 2L2 9L11 13" />
              </svg>
            </button>
          </div>
        </div>

        {!hasMessages && (
          <div className="quick-actions">
            {quickActions.map((action, idx) => (
              <button
                key={idx}
                className="quick-btn"
                onClick={() => setInput(action.action)}
              >
                <span className="icon">{action.icon}</span>
                {action.text}
              </button>
            ))}
          </div>
        )}
      </main>

      <footer className="footer">
        PentPython • AI Security Assistant
      </footer>
    </div>
  )
}

export default App
