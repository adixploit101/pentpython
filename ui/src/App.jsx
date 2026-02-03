import { useState } from 'react'
import './App.css'

const API_URL = ''

function App() {
  const [activeSection, setActiveSection] = useState('website')
  const [scanResults, setScanResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [url, setUrl] = useState('')
  const [file, setFile] = useState(null)
  const [playStoreUrl, setPlayStoreUrl] = useState('')
  const [apkInputType, setApkInputType] = useState('file') // 'file' or 'playstore'
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
    if (apkInputType === 'file' && !file) {
      setError('Please upload an APK file')
      return
    }
    if (apkInputType === 'playstore' && !playStoreUrl.trim()) {
      setError('Please enter a Google Play Store URL')
      return
    }
    setError('')
    setLoading(true)
    setScanResults(null)

    try {
      if (apkInputType === 'file') {
        const formData = new FormData()
        formData.append('file', file)
        const response = await fetch(`${API_URL}/scan/apk`, {
          method: 'POST',
          body: formData
        })
        if (!response.ok) throw new Error(`Scan failed: ${response.statusText}`)
        const data = await response.json()
        setScanResults(data)
        setFile(null)
      } else {
        // Play Store URL scanning
        const response = await fetch(`${API_URL}/scan/apk/playstore`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ play_store_url: playStoreUrl })
        })
        if (!response.ok) throw new Error(`Scan failed: ${response.statusText}`)
        const data = await response.json()
        setScanResults(data)
        setPlayStoreUrl('')
      }
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
      setFile(null)
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
      'Low': '#3b82f6'
    }
    return colors[severity] || '#6b7280'
  }

  const getSeverityIcon = (severity) => {
    if (severity === 'Critical' || severity === 'High') return '🔴'
    if (severity === 'Medium') return '🟡'
    return '🔵'
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="logo">
          <img src="/securescan_logo.png" alt="SecureScan" className="logo-icon" />
          <span>SecureScan</span>
        </div>

        <nav className="nav">
          <div className="nav-item active">
            <span className="icon">📊</span>
            <span>Dashboard</span>
          </div>
          <div className="nav-item">
            <span className="icon">🧠</span>
            <span>Threat Intelligence</span>
          </div>
          <div className="nav-item">
            <span className="icon">📈</span>
            <span>Analytics</span>
          </div>
          <div className="nav-item">
            <span className="icon">⚙️</span>
            <span>Settings</span>
          </div>
          <div className="nav-item">
            <span className="icon">ℹ️</span>
            <span>Information</span>
          </div>
        </nav>

        <div className="upgrade-box">
          <h3>Try the paid version!</h3>
          <p>Upgrade to the full version and stay one step ahead of every cyber threat.</p>
          <button className="upgrade-btn">Join today</button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="search-container">
            <span className="search-icon">🔍</span>
            <input type="text" placeholder="Search" className="search-input" />
            <button className="filter-btn">
              <span>🎯</span>
              <span>Filter</span>
            </button>
          </div>
          <div className="topbar-right">
            <button className="icon-button">🔔</button>
            <button className="icon-button active">☀️</button>
            <button className="icon-button">🌙</button>
            <div className="user-menu">
              <img src="https://ui-avatars.com/api/?name=Security+Admin&background=d97706&color=000" alt="User" />
              <div>
                <div className="user-name">Security Admin</div>
                <div className="user-status">● Verified</div>
              </div>
            </div>
          </div>
        </header>

        <div className="content-grid">
          {/* Main Scanner Section */}
          <div className="main-section">
            <div className="section-tabs">
              <button
                className={activeSection === 'website' ? 'tab active' : 'tab'}
                onClick={() => { setActiveSection('website'); setScanResults(null); setError(''); }}
              >
                Website Scanner
              </button>
              <button
                className={activeSection === 'apk' ? 'tab active' : 'tab'}
                onClick={() => { setActiveSection('apk'); setScanResults(null); setError(''); }}
              >
                APK Scanner
              </button>
              <button
                className={activeSection === 'code' ? 'tab active' : 'tab'}
                onClick={() => { setActiveSection('code'); setScanResults(null); setError(''); }}
              >
                Code Scanner
              </button>
            </div>

            {/* Scanner Input Area */}
            <div className="scanner-input">
              {activeSection === 'website' && (
                <div className="input-group">
                  <input
                    type="text"
                    placeholder="Enter website URL (e.g., https://example.com)"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    className="url-input"
                  />
                  <button onClick={handleWebsiteScan} disabled={loading} className="scan-button">
                    {loading ? 'Scanning...' : 'Start Scan'}
                  </button>
                </div>
              )}

              {activeSection === 'apk' && (
                <div className="apk-input-container">
                  <div className="input-type-toggle">
                    <button
                      className={apkInputType === 'file' ? 'toggle-btn active' : 'toggle-btn'}
                      onClick={() => { setApkInputType('file'); setError(''); }}
                    >
                      📁 Upload APK
                    </button>
                    <button
                      className={apkInputType === 'playstore' ? 'toggle-btn active' : 'toggle-btn'}
                      onClick={() => { setApkInputType('playstore'); setError(''); }}
                    >
                      🏪 Play Store Link
                    </button>
                  </div>

                  {apkInputType === 'file' ? (
                    <div className="input-group">
                      <input
                        type="file"
                        accept=".apk"
                        onChange={(e) => setFile(e.target.files[0])}
                        id="apk-upload"
                        style={{ display: 'none' }}
                      />
                      <label htmlFor="apk-upload" className="file-input-label">
                        {file ? file.name : 'Choose APK file'}
                      </label>
                      <button onClick={handleApkScan} disabled={loading || !file} className="scan-button">
                        {loading ? 'Analyzing...' : 'Analyze APK'}
                      </button>
                    </div>
                  ) : (
                    <div className="input-group">
                      <input
                        type="text"
                        placeholder="https://play.google.com/store/apps/details?id=..."
                        value={playStoreUrl}
                        onChange={(e) => setPlayStoreUrl(e.target.value)}
                        className="url-input"
                      />
                      <button onClick={handleApkScan} disabled={loading} className="scan-button">
                        {loading ? 'Analyzing...' : 'Analyze App'}
                      </button>
                    </div>
                  )}
                </div>
              )}

              {activeSection === 'code' && (
                <div className="input-group">
                  <input
                    type="file"
                    accept=".zip"
                    onChange={(e) => setFile(e.target.files[0])}
                    id="code-upload"
                    style={{ display: 'none' }}
                  />
                  <label htmlFor="code-upload" className="file-input-label">
                    {file ? file.name : 'Choose ZIP file'}
                  </label>
                  <button onClick={handleCodeScan} disabled={loading || !file} className="scan-button">
                    {loading ? 'Analyzing...' : 'Analyze Code'}
                  </button>
                </div>
              )}
            </div>

            {error && (
              <div className="error-box">
                <span>⚠️</span>
                <span>{error}</span>
              </div>
            )}

            {/* Results Table */}
            {scanResults && scanResults.results.vulnerabilities && (
              <div className="results-table-container">
                <table className="results-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Severity</th>
                      <th>Description</th>
                      <th>File</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.results.vulnerabilities.map((vuln, idx) => (
                      <tr key={idx}>
                        <td>{vuln.type}</td>
                        <td>
                          <span className="severity-badge" style={{ background: getSeverityColor(vuln.severity) }}>
                            {getSeverityIcon(vuln.severity)} {vuln.severity}
                          </span>
                        </td>
                        <td className="desc-cell">{vuln.description}</td>
                        <td className="file-cell">{vuln.file || 'N/A'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {scanResults && scanResults.results.vulnerabilities && scanResults.results.vulnerabilities.length === 0 && (
              <div className="no-results">
                <span className="check-icon">✅</span>
                <p>No vulnerabilities detected</p>
              </div>
            )}
          </div>

          {/* Sidebar Stats */}
          <div className="stats-sidebar">
            {scanResults && (
              <>
                <div className="stat-card">
                  <h3>Scan Summary</h3>
                  <div className="stat-row">
                    <span>Total Findings</span>
                    <span className="stat-value">{scanResults.results.vulnerabilities?.length || 0}</span>
                  </div>
                  {scanResults.results.security_score !== undefined && (
                    <div className="stat-row">
                      <span>Security Score</span>
                      <span className="stat-value">{scanResults.results.security_score}/100</span>
                    </div>
                  )}
                  {scanResults.results.files_scanned && (
                    <div className="stat-row">
                      <span>Files Scanned</span>
                      <span className="stat-value">{scanResults.results.files_scanned}</span>
                    </div>
                  )}
                  {scanResults.report_filename && (
                    <a href={`${API_URL}/download/${scanResults.report_filename}`} className="download-link" download>
                      📥 Download PDF Report
                    </a>
                  )}
                </div>

                {scanResults.results.security_score !== undefined && (
                  <div className="gauge-card">
                    <div className="gauge">
                      <svg viewBox="0 0 200 120">
                        <defs>
                          <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
                            <stop offset="0%" stopColor="#ef4444" />
                            <stop offset="50%" stopColor="#eab308" />
                            <stop offset="100%" stopColor="#10b981" />
                          </linearGradient>
                        </defs>
                        <path
                          d="M 20 100 A 80 80 0 0 1 180 100"
                          fill="none"
                          stroke="#2a2a2a"
                          strokeWidth="12"
                          strokeLinecap="round"
                        />
                        <path
                          d="M 20 100 A 80 80 0 0 1 180 100"
                          fill="none"
                          stroke="url(#gaugeGradient)"
                          strokeWidth="12"
                          strokeLinecap="round"
                          strokeDasharray={`${scanResults.results.security_score * 2.51} 251`}
                        />
                        <circle cx="100" cy="100" r="6" fill="#d97706" />
                      </svg>
                      <div className="gauge-value">
                        <div className="gauge-number">{scanResults.results.security_score}</div>
                        <div className="gauge-label">Score</div>
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}

            {!scanResults && (
              <div className="stat-card">
                <h3>Getting Started</h3>
                <p className="help-text">
                  Select a scanner type and provide the required input to begin security analysis.
                </p>
                <div className="scanner-info">
                  <div className="info-item">
                    <strong>🌐 Website Scanner</strong>
                    <span>SQL injection, XSS, CSRF, SSL/TLS analysis</span>
                  </div>
                  <div className="info-item">
                    <strong>📱 APK Scanner</strong>
                    <span>Hardcoded secrets, permissions, weak crypto</span>
                  </div>
                  <div className="info-item">
                    <strong>💻 Code Scanner</strong>
                    <span>Top 10 code vulnerabilities detection</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}

export default App
