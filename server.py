from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Dict, Any
from contextlib import asynccontextmanager
import uvicorn
import os
from agent import get_agent, FatalAPIError
import io
import sys
import re
import logging
from contextlib import redirect_stdout, redirect_stderr

# Suppress noisy loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("openai").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

def strip_ansi_codes(text: str) -> str:
    """Removes ANSI escape codes, box characters, and cleans output for web display."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    text = ansi_escape.sub('', text)
    text = re.sub(r'file://[^\s;]+', '', text)
    text = re.sub(r'8;id=\d+;[^\s]*', '', text)
    text = re.sub(r'C:\\[^\s;]+', '', text)
    text = re.sub(r'INFO\s+HTTP Request:.*\n?', '', text)
    text = re.sub(r'DEBUG.*\n?', '', text)
    box_chars = ['╭', '╮', '╰', '╯', '│', '─', '┌', '┐', '└', '┘', '├', '┤', '┬', '┴', '┼']
    for char in box_chars:
        text = text.replace(char, '')
    text = re.sub(r' {3,}', '  ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    lines = text.split('\n')
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not all(c in '-─═' for c in stripped):
            cleaned_lines.append(line.rstrip())
    return '\n'.join(cleaned_lines).strip()

agent = None
conversation_history = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    global agent
    agent = get_agent()
    yield

app = FastAPI(title="PentPython API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ChatRequest(BaseModel):
    message: str

class ChatResponse(BaseModel):
    response: str
    logs: str
    status: str

@app.options("/{rest_of_path:path}")
async def preflight_handler():
    return {}

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    global agent, conversation_history
    try:
        output_buffer = io.StringIO()
        with redirect_stdout(output_buffer), redirect_stderr(output_buffer):
            try:
                agent.run(request.message)
            except FatalAPIError as e:
                from agent import MockPentAgent
                agent = MockPentAgent()
                agent.run(request.message)
        logs = strip_ansi_codes(output_buffer.getvalue())
        conversation_history.append({"user": request.message, "assistant": logs})
        return ChatResponse(response=logs, logs=logs, status="success")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "healthy", "agent_type": type(agent).__name__}

@app.get("/history")
async def get_history():
    return {"history": conversation_history}

@app.post("/reset")
async def reset():
    global agent, conversation_history
    agent = get_agent()
    conversation_history = []
    return {"status": "reset_complete"}

@app.get("/download/{filename}")
async def download_file(filename: str):
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(os.getcwd(), safe_filename)
    if os.path.exists(file_path) and (safe_filename.endswith(".pdf") or safe_filename.endswith(".md")):
        return FileResponse(path=file_path, filename=safe_filename, media_type='application/octet-stream')
    else:
        raise HTTPException(status_code=404, detail="File not found or access denied")

# Serve static files (React frontend)
dist_path = os.path.join(os.getcwd(), "ui", "dist")

@app.get("/")
async def serve_index():
    index_file = os.path.join(dist_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"error": "Frontend build not found. Did you run npm run build?"}

# Mount the assets directory specifically
assets_path = os.path.join(dist_path, "assets")
if os.path.exists(assets_path):
    app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

# Catch-all for SPA routing (redirects to index.html for unknown routes)
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    # Skip API routes
    if full_path.startswith(("chat", "health", "history", "reset", "download")):
        raise HTTPException(status_code=404, detail="API route not found")
        
    # Check for other static files in dist root (like robots.txt, favicon.ico)
    file_path = os.path.join(dist_path, full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
        
    # Default to index.html for SPA
    index_file = os.path.join(dist_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    
    raise HTTPException(status_code=404, detail="Not found")



if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=PORT)
