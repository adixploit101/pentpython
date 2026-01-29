import { useState } from 'react'

const API_URL = ''

function WebsiteScanner({ onScanComplete, onScanStart, loading, setLoading }) {
    const [url, setUrl] = useState('')
    const [error, setError] = useState('')

    const handleScan = async () => {
        if (!url.trim()) {
            setError('Please enter a URL')
            return
        }

        setError('')
        setLoading(true)
        onScanStart()

        try {
            const response = await fetch(`${API_URL}/scan/website`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            })

            if (!response.ok) {
                throw new Error(`Scan failed: ${response.statusText}`)
            }

            const data = await response.json()
            onScanComplete(data)
        } catch (err) {
            setError(err.message)
            setLoading(false)
        }
    }

    return (
        <div className="scanner-content">
            <div className="scanner-header">
                <h2>🌐 Website Security Scanner</h2>
                <p>Comprehensive vulnerability assessment for web applications</p>
            </div>

            <div className="scanner-form">
                <div className="form-group">
                    <label>Website URL</label>
                    <input
                        type="text"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        placeholder="https://example.com"
                        disabled={loading}
                        onKeyPress={(e) => e.key === 'Enter' && handleScan()}
                    />
                </div>

                {error && <div className="error-message">{error}</div>}

                <button
                    className="scan-button"
                    onClick={handleScan}
                    disabled={loading}
                >
                    {loading ? (
                        <>
                            <span className="spinner"></span>
                            Scanning...
                        </>
                    ) : (
                        <>
                            <span>🔍</span>
                            Start Scan
                        </>
                    )}
                </button>
            </div>

            <div className="scanner-features">
                <h3>What We Check:</h3>
                <div className="features-grid">
                    <div className="feature-item">✓ SQL Injection</div>
                    <div className="feature-item">✓ XSS Vulnerabilities</div>
                    <div className="feature-item">✓ CSRF Protection</div>
                    <div className="feature-item">✓ Security Headers</div>
                    <div className="feature-item">✓ SSL/TLS Configuration</div>
                    <div className="feature-item">✓ Directory Traversal</div>
                    <div className="feature-item">✓ Information Disclosure</div>
                    <div className="feature-item">✓ Authentication Issues</div>
                </div>
            </div>
        </div>
    )
}

export default WebsiteScanner
