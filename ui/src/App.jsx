import { useState } from 'react'
import './App.css'

const API_URL = ''

function App() {
  const [activeScanner, setActiveScanner] = useState(null)
  const [scanResults, setScanResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [url, setUrl] = useState('')
  const [file, setFile] = useState(null)
  const [error, setError] = useState('')

  const handleWebsiteScan = async () => {
    if (!url.trim()) {
      setError('Please enter a URL')
      return
    }
    setError('')
    setLoading(true)
    setScanResults(null)

    try {
      const response = await fetch(`${API_URL}/scan/website`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      })
      if (!response.ok) throw new Error(`Scan failed: ${response.statusText}`)
      const data = await response.json()
      setScanResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleApkScan = async () => {
    if (!file) {
      setError('Please upload an APK file')
      return
    }
    setError('')
    setLoading(true)
    setScanResults(null)

    try {
      const formData = new FormData()
      formData.append('file', file)
      const response = await fetch(`${API_URL}/scan/apk`, {
        method: 'POST',
        body: formData
      })
      if (!response.ok) throw new Error(`Scan failed: ${response.statusText}`)
      const data = await response.json()
      setScanResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const handleCodeScan = async () => {
    if (!file) {
      setError('Please upload a ZIP file')
      return
    }
    setError('')
    setLoading(true)
    setScanResults(null)

    try {
      const formData = new FormData()
      formData.append('file', file)
      const response = await fetch(`${API_URL}/scan/project`, {
        method: 'POST',
        body: formData
      })
      if (!response.ok) throw new Error(`Scan failed: ${response.statusText}`)
      const data = await response.json()
      setScanResults(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': '#ef4444',
      'High': '#f97316',
      'Medium': '#eab308',
      'Low': '#3b82f6',
      'Info': '#6b7280'
    }
    return colors[severity] || colors['Info']
  }

  return (
    <div className="app">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon">🛡️</div>
          <span className="logo-text">PentPython</span>
        </div>

        <nav className="nav">
          <div className="nav-item active">
            <span className="nav-icon">📊</span>
            <span>Dashboard</span>
          </div>
          <div className="nav-item">
            <span className="nav-icon">🔍</span>
            <span>Scanners</span>
          </div>
          <div className="nav-item">
            <span className="nav-icon">📈</span>
            <span>Analytics</span>
          </div>
          <div className="nav-item">
            <span className="nav-icon">⚙️</span>
            <span>Settings</span>
          </div>
        </nav>

        <div className="sidebar-footer">
          <div className="upgrade-card">
            <h3>Try the paid version!</h3>
            <p>Upgrade to the full version and stay one step ahead of every cyber threat.</p>
            <button className="upgrade-btn">Join today</button>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header className="header">
          <div className="search-bar">
            <span className="search-icon">🔍</span>
            <input type="text" placeholder="Search" />
          </div>
          <div className="header-actions">
            <button className="icon-btn">🔔</button>
            <button className="icon-btn">☀️</button>
            <button className="icon-btn">🌙</button>
            <div className="user-profile">
              <img src="https://ui-avatars.com/api/?name=Security+User&background=d97706&color=fff" alt="User" />
              <span>Security User</span>
            </div>
          </div>
        </header>

        <div className="content">
          <h1 className="page-title">Security Scanners</h1>

          {/* Scanner Cards Grid */}
          <div className="scanner-grid">
            {/* Website Scanner Card */}
            <div className="scanner-card">
              <div className="card-header">
                <h2>🌐 Website Scanner</h2>
                <p>Comprehensive web vulnerability assessment</p>
              </div>
              <div className="card-body">
                <input
                  type="text"
                  className="input-field"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  disabled={loading && activeScanner === 'website'}
                />
                <button
                  className="scan-btn"
                  onClick={() => {
                    setActiveScanner('website')
                    handleWebsiteScan()
                  }}
                  disabled={loading && activeScanner === 'website'}
                >
                  {loading && activeScanner === 'website' ? 'Scanning...' : 'Start Scan'}
                </button>
                <div className="features">
                  <span className="feature-tag">SQL Injection</span>
                  <span className="feature-tag">XSS</span>
                  <span className="feature-tag">CSRF</span>
                  <span className="feature-tag">SSL/TLS</span>
                </div>
              </div>
            </div>

            {/* APK Scanner Card */}
            <div className="scanner-card">
              <div className="card-header">
                <h2>📱 APK Scanner</h2>
                <p>Android application security analysis</p>
              </div>
              <div className="card-body">
                <div className="file-upload">
                  <input
                    type="file"
                    accept=".apk"
                    onChange={(e) => setFile(e.target.files[0])}
                    id="apk-file"
                    style={{ display: 'none' }}
                  />
                  <label htmlFor="apk-file" className="file-label">
                    {file && activeScanner === 'apk' ? file.name : 'Choose APK file'}
                  </label>
                </div>
                <button
                  className="scan-btn"
                  onClick={() => {
                    setActiveScanner('apk')
                    handleApkScan()
                  }}
                  disabled={loading && activeScanner === 'apk'}
                >
                  {loading && activeScanner === 'apk' ? 'Analyzing...' : 'Analyze APK'}
                </button>
                <div className="features">
                  <span className="feature-tag">Hardcoded Secrets</span>
                  <span className="feature-tag">Permissions</span>
                  <span className="feature-tag">Weak Crypto</span>
                  <span className="feature-tag">Network Security</span>
                </div>
              </div>
            </div>

            {/* Code Scanner Card */}
            <div className="scanner-card">
              <div className="card-header">
                <h2>💻 Code Scanner</h2>
                <p>Static analysis for Top 10 vulnerabilities</p>
              </div>
              <div className="card-body">
                <div className="file-upload">
                  <input
                    type="file"
                    accept=".zip"
                    onChange={(e) => setFile(e.target.files[0])}
                    id="code-file"
                    style={{ display: 'none' }}
                  />
                  <label htmlFor="code-file" className="file-label">
                    {file && activeScanner === 'code' ? file.name : 'Choose ZIP file'}
                  </label>
                </div>
                <button
                  className="scan-btn"
                  onClick={() => {
                    setActiveScanner('code')
                    handleCodeScan()
                  }}
                  disabled={loading && activeScanner === 'code'}
                >
                  {loading && activeScanner === 'code' ? 'Analyzing...' : 'Analyze Code'}
                </button>
                <div className="features">
                  <span className="feature-tag">Rate Limiting</span>
                  <span className="feature-tag">API Keys</span>
                  <span className="feature-tag">CORS</span>
                  <span className="feature-tag">Input Validation</span>
                </div>
              </div>
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div className="error-banner">
              <span>⚠️</span>
              <span>{error}</span>
            </div>
          )}

          {/* Results Section */}
          {scanResults && (
            <div className="results-section">
              <div className="results-header">
                <h2>Scan Results</h2>
                {scanResults.report_filename && (
                  <a
                    href={`${API_URL}/download/${scanResults.report_filename}`}
                    className="download-btn"
                    download
                  >
                    📥 Download PDF Report
                  </a>
                )}
              </div>

              {/* Security Score */}
              {scanResults.results.security_score !== undefined && (
                <div className="score-card">
                  <div className="score-circle">
                    <svg viewBox="0 0 100 100">
                      <circle cx="50" cy="50" r="40" fill="none" stroke="#2a2a2a" strokeWidth="8" />
                      <circle
                        cx="50"
                        cy="50"
                        r="40"
                        fill="none"
                        stroke="#d97706"
                        strokeWidth="8"
                        strokeDasharray={`${scanResults.results.security_score * 2.51} 251`}
                        transform="rotate(-90 50 50)"
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="score-value">
                      <span className="score-number">{scanResults.results.security_score}</span>
                      <span className="score-label">Security Score</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Vulnerabilities */}
              <div className="vulnerabilities">
                <h3>Vulnerabilities Found: {scanResults.results.vulnerabilities?.length || 0}</h3>
                {scanResults.results.vulnerabilities && scanResults.results.vulnerabilities.length > 0 ? (
                  <div className="vuln-list">
                    {scanResults.results.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="vuln-card" style={{ borderLeftColor: getSeverityColor(vuln.severity) }}>
                        <div className="vuln-header">
                          <span className="vuln-title">{vuln.type}</span>
                          <span
                            className="vuln-severity"
                            style={{ backgroundColor: getSeverityColor(vuln.severity) }}
                          >
                            {vuln.severity}
                          </span>
                        </div>
                        <p className="vuln-desc">{vuln.description}</p>
                        {vuln.file && <p className="vuln-file">📄 {vuln.file}</p>}
                        <div className="vuln-fix">
                          <strong>Fix:</strong> {vuln.remediation}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="no-vulns">
                    <span className="success-icon">✅</span>
                    <p>No vulnerabilities detected!</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}

export default App
