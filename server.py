import os
import sys
import shutil
import logging
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
from contextlib import asynccontextmanager
import uvicorn
import aiofiles
from datetime import datetime

# Local imports
from scanners import WebsiteScanner, ApkScanner, CodeScanner
from report_generator import SecurityReport

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Base paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
dist_path = os.path.join(BASE_DIR, "ui", "dist")
uploads_path = os.path.join(BASE_DIR, "uploads")
reports_path = os.path.join(BASE_DIR, "reports")

# Create directories
os.makedirs(uploads_path, exist_ok=True)
os.makedirs(reports_path, exist_ok=True)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("PentPython Multi-Scanner Platform Starting...")
    yield
    logger.info("Shutting down...")

app = FastAPI(title="PentPython Security Scanner", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response Models
class WebsiteScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    results: dict
    report_filename: Optional[str] = None

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "2.0.0", "scanners": ["website", "apk", "code"]}

@app.post("/scan/website", response_model=ScanResponse)
async def scan_website(request: WebsiteScanRequest):
    """Scan a website for vulnerabilities"""
    try:
        logger.info(f"Starting website scan for: {request.url}")
        
        # Run scanner
        scanner = WebsiteScanner(request.url)
        results = scanner.scan()
        
        # Generate PDF report
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = SecurityReport(
            target=request.url,
            scan_type="Website Security Scan",
            vulnerabilities=results.get('vulnerabilities', [])
        )
        
        report_files = report.save()
        pdf_filename = os.path.basename(report_files['pdf'])
        
        return ScanResponse(
            scan_id=scan_id,
            status="completed",
            results=results,
            report_filename=pdf_filename
        )
    except Exception as e:
        logger.error(f"Website scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/apk", response_model=ScanResponse)
async def scan_apk(file: UploadFile = File(...)):
    """Scan an APK file for security vulnerabilities"""
    try:
        logger.info(f"Starting APK scan for: {file.filename}")
        
        # Validate file type
        if not file.filename.endswith('.apk'):
            raise HTTPException(status_code=400, detail="Only .apk files are allowed")
        
        # Save uploaded file
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        apk_path = os.path.join(uploads_path, f"{scan_id}_{file.filename}")
        
        async with aiofiles.open(apk_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        # Run scanner
        scanner = ApkScanner(apk_path)
        results = scanner.scan()
        
        # Generate PDF report
        report = SecurityReport(
            target=file.filename,
            scan_type="APK Security Analysis",
            vulnerabilities=results.get('vulnerabilities', [])
        )
        
        report_files = report.save()
        pdf_filename = os.path.basename(report_files['pdf'])
        
        # Cleanup uploaded file
        try:
            os.remove(apk_path)
        except:
            pass
        
        return ScanResponse(
            scan_id=scan_id,
            status="completed",
            results=results,
            report_filename=pdf_filename
        )
    except Exception as e:
        logger.error(f"APK scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/project", response_model=ScanResponse)
async def scan_project(file: UploadFile = File(...)):
    """Scan a code project (ZIP) for vulnerabilities"""
    try:
        logger.info(f"Starting code project scan for: {file.filename}")
        
        # Validate file type
        if not file.filename.endswith('.zip'):
            raise HTTPException(status_code=400, detail="Only .zip files are allowed")
        
        # Save uploaded file
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_path = os.path.join(uploads_path, f"{scan_id}_{file.filename}")
        
        async with aiofiles.open(zip_path, 'wb') as f:
            content = await file.read()
            await f.write(content)
        
        # Run scanner
        scanner = CodeScanner(zip_path)
        results = scanner.scan()
        
        # Generate PDF report
        report = SecurityReport(
            target=file.filename,
            scan_type="Code Security Analysis",
            vulnerabilities=results.get('vulnerabilities', [])
        )
        
        report_files = report.save()
        pdf_filename = os.path.basename(report_files['pdf'])
        
        # Cleanup uploaded file and extracted directory
        try:
            os.remove(zip_path)
            extract_path = zip_path.replace('.zip', '_extracted')
            if os.path.exists(extract_path):
                shutil.rmtree(extract_path)
        except:
            pass
        
        return ScanResponse(
            scan_id=scan_id,
            status="completed",
            results=results,
            report_filename=pdf_filename
        )
    except Exception as e:
        logger.error(f"Code scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download/{filename}")
async def download_report(filename: str):
    """Download a generated report"""
    safe_filename = os.path.basename(filename)
    file_path = os.path.join(os.getcwd(), safe_filename)
    
    if os.path.exists(file_path) and (safe_filename.endswith(".pdf") or safe_filename.endswith(".md")):
        return FileResponse(path=file_path, filename=safe_filename, media_type='application/octet-stream')
    
    raise HTTPException(status_code=404, detail="Report not found")

# Serve frontend
@app.api_route("/", methods=["GET", "HEAD"])
async def serve_index():
    index_file = os.path.join(dist_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"error": "Frontend not found", "path": dist_path}

# Mount static assets
assets_path = os.path.join(dist_path, "assets")
if os.path.exists(assets_path):
    app.mount("/assets", StaticFiles(directory=assets_path), name="assets")

@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    # API protection
    if full_path.startswith(("scan", "health", "download")):
        raise HTTPException(status_code=404)
    
    # Check static files
    file_path = os.path.join(dist_path, full_path)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    
    # SPA fallback
    index_file = os.path.join(dist_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    
    raise HTTPException(status_code=404, detail="Not found")

if __name__ == "__main__":
    PORT = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=PORT)
