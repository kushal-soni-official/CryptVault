import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from cryptvault.core.models import init_db, list_files, save_file_metadata, get_file_metadata, delete_file, FILES_DIR

logger = logging.getLogger(__name__)

# Maximum upload size: 100 MB
MAX_UPLOAD_BYTES = 100 * 1024 * 1024

app = FastAPI(title="CryptVault Web", description="Zero-Trust Encrypted File Storage")

# CORS — restricted to localhost only
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Nonce", "X-Tag", "X-Salt"],
)

# Setup paths (cross-platform with pathlib)
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Ensure DB is initialized
init_db()


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    """Serve the main vault page."""
    files = list_files()
    return templates.TemplateResponse(request=request, name="index.html", context={"files": files})


@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    nonce: str = Form(""),
    tag: str = Form(""),
    salt: str = Form(""),
    original_size: int = Form(0),
):
    """
    Receives encrypted file blobs from the browser.
    The server never sees the plaintext — only ciphertext.
    """
    # Validate nonce is a hex string of correct length (12 bytes = 24 hex chars)
    if not nonce or len(nonce) != 24:
        raise HTTPException(status_code=400, detail="Invalid nonce: must be 24 hex characters (12 bytes)")
    try:
        bytes.fromhex(nonce)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid nonce: must be valid hex string")

    # Validate salt
    if not salt or len(salt) < 16:
        raise HTTPException(status_code=400, detail="Invalid salt: must be provided")

    file_id = str(uuid.uuid4())
    output_path = FILES_DIR / file_id

    try:
        content = await file.read()

        # Enforce file size limit
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size is {MAX_UPLOAD_BYTES // (1024*1024)} MB"
            )

        with open(output_path, "wb") as f:
            f.write(content)

        save_file_metadata(file_id, file.filename, original_size, nonce, tag, source="web")
        # Store salt in a sidecar file for retrieval during download
        salt_path = FILES_DIR / f"{file_id}.salt"
        with open(salt_path, "w") as f:
            f.write(salt)

        logger.info(f"Asset successfully secured: {file_id} ({file.filename})")
        return {"id": file_id, "name": file.filename, "size": original_size, "message": "Encryption complete. Asset secured."}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Upload failed")
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

    # Read salt from sidecar file
    salt_path = FILES_DIR / f"{file_id}.salt"
    salt_hex = ""
    if salt_path.exists():
        with open(salt_path, "r") as f:
            salt_hex = f.read().strip()

    return FileResponse(
        path=file_path,
        filename=f"{meta['original_name']}.encrypted",
        media_type="application/octet-stream",
        headers={
            "X-Nonce": meta['nonce'],
            "X-Tag": meta.get('tag', ''),
            "X-Salt": salt_hex,
            "Access-Control-Expose-Headers": "X-Nonce, X-Tag, X-Salt",
        }
    )


@app.delete("/api/files/{file_id}")
async def delete_file_endpoint(file_id: str):
    """Delete an encrypted file from the vault."""
    # Also delete the salt sidecar file
    salt_path = FILES_DIR / f"{file_id}.salt"
    if salt_path.exists():
        salt_path.unlink()

    if delete_file(file_id):
        logger.info("File deleted via web: %s", file_id)
        return {"message": "File deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="File not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("cryptvault.web.app:app", host="127.0.0.1", port=8000, reload=True)
