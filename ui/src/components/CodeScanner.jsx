import { useState, useRef } from 'react'

const API_URL = ''

function CodeScanner({ onScanComplete, onScanStart, loading, setLoading }) {
    const [file, setFile] = useState(null)
    const [error, setError] = useState('')
    const [dragActive, setDragActive] = useState(false)
    const fileInputRef = useRef(null)

    const handleDrag = (e) => {
        e.preventDefault()
        e.stopPropagation()
        if (e.type === "dragenter" || e.type === "dragover") {
            setDragActive(true)
        } else if (e.type === "dragleave") {
            setDragActive(false)
        }
    }

    const handleDrop = (e) => {
        e.preventDefault()
        e.stopPropagation()
        setDragActive(false)

        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            const droppedFile = e.dataTransfer.files[0]
            if (droppedFile.name.endsWith('.zip')) {
                setFile(droppedFile)
                setError('')
            } else {
                setError('Please upload a ZIP file')
            }
        }
    }

    const handleFileChange = (e) => {
        if (e.target.files && e.target.files[0]) {
            const selectedFile = e.target.files[0]
            if (selectedFile.name.endsWith('.zip')) {
                setFile(selectedFile)
                setError('')
            } else {
                setError('Please upload a ZIP file')
            }
        }
    }

    const handleScan = async () => {
        if (!file) {
            setError('Please upload a ZIP file')
            return
        }

        setError('')
        setLoading(true)
        onScanStart()

        try {
            const formData = new FormData()
            formData.append('file', file)

            const response = await fetch(`${API_URL}/scan/project`, {
                method: 'POST',
                body: formData
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
                <h2>💻 Code Project Scanner</h2>
                <p>Static analysis for source code - Top 10 Vibe Code Vulnerabilities</p>
            </div>

            <div className="scanner-form">
                <div
                    className={`file-upload-area ${dragActive ? 'drag-active' : ''} ${file ? 'has-file' : ''}`}
                    onDragEnter={handleDrag}
                    onDragLeave={handleDrag}
                    onDragOver={handleDrag}
                    onDrop={handleDrop}
                    onClick={() => fileInputRef.current?.click()}
                >
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept=".zip"
                        onChange={handleFileChange}
                        style={{ display: 'none' }}
                    />

                    {file ? (
                        <div className="file-info">
                            <span className="file-icon">📦</span>
                            <div className="file-details">
                                <div className="file-name">{file.name}</div>
                                <div className="file-size">{(file.size / 1024 / 1024).toFixed(2)} MB</div>
                            </div>
                            <button
                                className="remove-file"
                                onClick={(e) => {
                                    e.stopPropagation()
                                    setFile(null)
                                }}
                            >
                                ✕
                            </button>
                        </div>
                    ) : (
                        <div className="upload-prompt">
                            <span className="upload-icon">💻</span>
                            <p className="upload-text">Drop ZIP file here or click to browse</p>
                            <p className="upload-hint">Maximum file size: 100MB</p>
                        </div>
                    )}
                </div>

                {error && <div className="error-message">{error}</div>}

                <button
                    className="scan-button"
                    onClick={handleScan}
                    disabled={loading || !file}
                >
                    {loading ? (
                        <>
                            <span className="spinner"></span>
                            Analyzing Code...
                        </>
                    ) : (
                        <>
                            <span>🔍</span>
                            Analyze Code
                        </>
                    )}
                </button>
            </div>

            <div className="scanner-features">
                <h3>Top 10 Vibe Code Vulnerabilities:</h3>
                <div className="features-grid">
                    <div className="feature-item">1. Rate Limit Bypassing</div>
                    <div className="feature-item">2. API Key Exposure</div>
                    <div className="feature-item">3. No Authentication</div>
                    <div className="feature-item">4. CORS Misconfiguration</div>
                    <div className="feature-item">5. No Input Validation</div>
                    <div className="feature-item">6. Typosquatting</div>
                    <div className="feature-item">7. Missing Sanitization</div>
                    <div className="feature-item">8. Outdated Dependencies</div>
                    <div className="feature-item">9. Business Logic Flaws</div>
                    <div className="feature-item">10. No Error Handling</div>
                </div>
            </div>
        </div>
    )
}

export default CodeScanner
