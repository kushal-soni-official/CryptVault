from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from pathlib import Path
import os
import uuid

from cryptvault.core.models import init_db, list_files, save_file_metadata, get_file_metadata, FILES_DIR

app = FastAPI(title="CryptVault Web")

# Setup paths
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Ensure DB is initialized
init_db()

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    files = list_files()
    return templates.TemplateResponse("index.html", {"request": request, "files": files})

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...), 
    nonce: str = "", 
    tag: str = "", 
    original_size: int = 0
):
    """
    Receives encrypted file blobs. 
    The server does not have the key, and only sees the ciphertext.
    """
    file_id = str(uuid.uuid4())
    output_path = FILES_DIR / file_id
    
    try:
        content = await file.read()
        with open(output_path, "wb") as f:
            f.write(content)
            
        save_file_metadata(file_id, file.filename, original_size, nonce, tag)
        return {"id": file_id, "message": "File uploaded securely"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/download/{file_id}")
async def download_file(file_id: str):
    """Serve the encrypted file blob to the client for local decryption."""
    meta = get_file_metadata(file_id)
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")
        
    file_path = FILES_DIR / file_id
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Encrypted file missing from disk")
        
    return FileResponse(
        path=file_path, 
        filename=f"{meta['original_name']}.encrypted", 
        media_type="application/octet-stream",
        headers={
            "X-Nonce": meta['nonce'],
            "X-Tag": meta['tag'],
            "Access-Control-Expose-Headers": "X-Nonce, X-Tag"
        }
    )

if __name__ == "__main__":
    # In a real environment, you'd run this with SSL explicitly via uvicorn parameters.
    # Instruction: python -m cryptvault.web.app
    uvicorn.run("cryptvault.web.app:app", host="127.0.0.1", port=8000, reload=True)
