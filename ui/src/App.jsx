import { useState } from 'react'
import './App.css'
import WebsiteScanner from './components/WebsiteScanner'
import ApkScanner from './components/ApkScanner'
import CodeScanner from './components/CodeScanner'

const API_URL = ''

function App() {
  const [activeTab, setActiveTab] = useState('website')
  const [scanResults, setScanResults] = useState(null)
  const [loading, setLoading] = useState(false)

  const tabs = [
    { id: 'website', name: 'Website Scanner', icon: '🌐' },
    { id: 'apk', name: 'APK Scanner', icon: '📱' },
    { id: 'code', name: 'Code Scanner', icon: '💻' }
  ]

  const handleScanComplete = (results) => {
    setScanResults(results)
    setLoading(false)
  }

  const handleScanStart = () => {
    setLoading(false)
    setScanResults(null)
  }

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': '#DC2626',
      'High': '#EA580C',
      'Medium': '#CA8A04',
      'Low': '#2563EB',
      'Info': '#6B7280'
    }
    return colors[severity] || colors['Info']
  }

  const getSeverityBadge = (severity) => {
    return (
      <span
        className="severity-badge"
        style={{ backgroundColor: getSeverityColor(severity) }}
      >
        {severity}
      </span>
    )
  }

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <h1>PentPython</h1>
            <span className="version">v2.0</span>
          </div>
          <div className="header-subtitle">
            Multi-Scanner Security Platform
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="main-container">
        {/* Tab Navigation */}
        <div className="tabs">
          {tabs.map(tab => (
            <button
              key={tab.id}
              className={`tab ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => {
                setActiveTab(tab.id)
                setScanResults(null)
              }}
            >
              <span className="tab-icon">{tab.icon}</span>
              <span className="tab-name">{tab.name}</span>
            </button>
          ))}
        </div>

        {/* Scanner Content */}
        <div className="scanner-container">
          <div className="scanner-panel">
            {activeTab === 'website' && (
              <WebsiteScanner
                onScanComplete={handleScanComplete}
                onScanStart={handleScanStart}
                loading={loading}
                setLoading={setLoading}
              />
            )}
            {activeTab === 'apk' && (
              <ApkScanner
                onScanComplete={handleScanComplete}
                onScanStart={handleScanStart}
                loading={loading}
                setLoading={setLoading}
              />
            )}
            {activeTab === 'code' && (
              <CodeScanner
                onScanComplete={handleScanComplete}
                onScanStart={handleScanStart}
                loading={loading}
                setLoading={setLoading}
              />
            )}
          </div>

          {/* Results Panel */}
          {scanResults && (
            <div className="results-panel">
              <div className="results-header">
                <h2>Scan Results</h2>
                {scanResults.report_filename && (
                  <a
                    href={`${API_URL}/download/${scanResults.report_filename}`}
                    className="download-btn"
                    download
                  >
                    <span>📥</span>
                    Download PDF Report
                  </a>
                )}
              </div>

              {/* Security Score */}
              {scanResults.results.security_score !== undefined && (
                <div className="security-score">
                  <div className="score-circle">
                    <svg viewBox="0 0 100 100">
                      <circle cx="50" cy="50" r="45" fill="none" stroke="#e5e7eb" strokeWidth="8" />
                      <circle
                        cx="50"
                        cy="50"
                        r="45"
                        fill="none"
                        stroke={scanResults.results.security_score >= 70 ? '#10b981' : scanResults.results.security_score >= 40 ? '#f59e0b' : '#ef4444'}
                        strokeWidth="8"
                        strokeDasharray={`${scanResults.results.security_score * 2.827} 283`}
                        transform="rotate(-90 50 50)"
                      />
                    </svg>
                    <div className="score-text">
                      <span className="score-number">{scanResults.results.security_score}</span>
                      <span className="score-label">Security Score</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Scan Info */}
              <div className="scan-info">
                {scanResults.results.files_scanned && (
                  <div className="info-item">
                    <span className="info-label">Files Scanned:</span>
                    <span className="info-value">{scanResults.results.files_scanned}</span>
                  </div>
                )}
                {scanResults.results.languages && scanResults.results.languages.length > 0 && (
                  <div className="info-item">
                    <span className="info-label">Languages:</span>
                    <span className="info-value">{scanResults.results.languages.join(', ')}</span>
                  </div>
                )}
                {scanResults.results.permissions && scanResults.results.permissions.length > 0 && (
                  <div className="info-item">
                    <span className="info-label">Permissions:</span>
                    <span className="info-value">{scanResults.results.permissions.length}</span>
                  </div>
                )}
              </div>

              {/* Vulnerabilities */}
              <div className="vulnerabilities-section">
                <h3>Vulnerabilities Found: {scanResults.results.vulnerabilities?.length || 0}</h3>

                {scanResults.results.vulnerabilities && scanResults.results.vulnerabilities.length > 0 ? (
                  <div className="vulnerability-list">
                    {scanResults.results.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="vulnerability-card">
                        <div className="vuln-header">
                          <div className="vuln-title">
                            <span className="vuln-icon">⚠️</span>
                            <span>{vuln.type}</span>
                          </div>
                          {getSeverityBadge(vuln.severity)}
                        </div>
                        <div className="vuln-description">{vuln.description}</div>
                        {vuln.file && (
                          <div className="vuln-file">
                            <span className="file-icon">📄</span>
                            {vuln.file}
                          </div>
                        )}
                        <div className="vuln-remediation">
                          <strong>Remediation:</strong> {vuln.remediation}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="no-vulnerabilities">
                    <span className="success-icon">✅</span>
                    <p>No vulnerabilities detected!</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="footer">
        <p>PentPython Security Scanner • Powered by Advanced AI Analysis</p>
      </footer>
    </div>
  )
}

export default App
