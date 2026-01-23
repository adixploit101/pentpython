import os
import sys
import re
import logging
import io
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Dict, Any
from contextlib import asynccontextmanager, redirect_stdout, redirect_stderr
import uvicorn
import shutil

# Local imports
from exceptions import FatalAPIError
from agent import get_agent



logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dist_path = os.path.join(BASE_DIR, "ui", "dist")

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
    logger.info("Initializing Agent...")
    try:
        agent = get_agent()
        logger.info(f"Agent initialized: {type(agent).__name__}")
    except Exception as e:
        logger.error(f"Failed to initialize agent: {e}")
    yield

app = FastAPI(title="PentPython API", version="1.1.0", lifespan=lifespan)

@app.get("/health")
async def health():
    return {"status": "healthy", "message": "Render service is up"}

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
    if not agent:
        agent = get_agent()
    
    try:
        # Agent now returns logs directly
        logs = agent.run(request.message)
        
        if not logs:
            logs = "Agent executed but produced no output."
            
        conversation_history.append({"user": request.message, "assistant": logs})
        return ChatResponse(response=logs, logs=logs, status="success")
    except Exception as e:
        logger.error(f"Chat Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
async def health():
    return {"status": "healthy", "agent": type(agent).__name__ if agent else "Not Initialized"}

@app.get("/history")
async def get_history():
    return {"history": conversation_history}

@app.post("/reset")
async def reset():
    global agent, conversation_history
    agent = get_agent()
    conversation_history = []
    return {"status": "reset_complete"}

@app.get("/debug")
async def debug():
    # Check for system dependencies
    whois_exists = shutil.which("whois") is not None
    dig_exists = shutil.which("dig") is not None
    
    return {
        "status": "online",
        "env": {
            "openai_key": bool(os.getenv("OPENAI_API_KEY")),
            "gemini_key": bool(os.getenv("GEMINI_API_KEY")),
            "port": os.getenv("PORT", "8000")
        },
        "system": {
            "cwd": os.getcwd(),
            "base_dir": BASE_DIR,
            "python": sys.version,
            "whois": whois_exists,
            "dig": dig_exists
        },
        "frontend": {
            "dist_path": dist_path,
            "dist_exists": os.path.exists(dist_path),
            "index_exists": os.path.exists(os.path.join(dist_path, "index.html"))
        }
    }

@app.get("/download/{filename}")
async def download_file(filename: str):
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(os.getcwd(), safe_filename)
    if os.path.exists(file_path) and (safe_filename.endswith(".pdf") or safe_filename.endswith(".md")):
        return FileResponse(path=file_path, filename=safe_filename, media_type='application/octet-stream')
    raise HTTPException(status_code=404, detail="File not found")

# --- STATIC FILE SERVING ---

@app.api_route("/", methods=["GET", "HEAD"])
async def serve_index():
    index_file = os.path.join(dist_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {
        "error": "Frontend build not found.",
        "details": f"Checked path: {index_file}",
        "advice": "Ensure ui/dist is uploaded to GitHub and not ignored."
    }


assets_path = os.path.join(dist_path, "assets")
if os.path.exists(assets_path):
    app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    # API Protection
    if full_path.startswith(("chat", "health", "history", "reset", "download", "debug")):
        raise HTTPException(status_code=404)
        
    # Check static files
    file_path = os.path.join(dist_path, full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
        
    # SPA Fallback
    index_file = os.path.join(dist_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    
    raise HTTPException(status_code=404, detail="Not found")

if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=PORT)
