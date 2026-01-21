# PentPython - Quick Start Guide

## Running the Full Application

### 1. Start the Backend Server
```powershell
cd f:\Cy_Agent\pentpython
python server.py
```
The API will run on `http://localhost:8000`

### 2. Start the Frontend (in a new terminal)
```powershell
cd f:\Cy_Agent\pentpython\ui
npm run dev
```
The UI will open at `http://localhost:5173`

### 3. Set API Key (Optional)
Set either key before starting the backend:
```powershell
$env:OPENAI_API_KEY="sk-..."
# OR
$env:GEMINI_API_KEY="your-key"
```

## Features
- 🔐 AI-powered security operations
- 🎨 Futuristic cyber aesthetic
- ⚡ Real-time chat interface
- 🛠️ Port scanning & file inspection
- 🔄 Auto-fallback to simulation mode

## Architecture
- **Backend**: FastAPI + Python (port 8000)
- **Frontend**: React + Vite (port 5173)
- **Agent**: Multi-provider (OpenAI/Gemini/Mock)
