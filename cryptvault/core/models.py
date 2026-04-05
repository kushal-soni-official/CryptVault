import sqlite3
import logging
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Cross-platform vault directory: ~/.cryptvault on both Windows and Linux
VAULT_DIR = Path.home() / ".cryptvault"
DB_PATH = VAULT_DIR / "vault.db"
FILES_DIR = VAULT_DIR / "files"

def _get_conn() -> sqlite3.Connection:
    """Create a database connection with row factory enabled."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the vault directory structure and database schema."""
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(str(DB_PATH)) as conn:
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                original_name TEXT,
                size INTEGER,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                nonce TEXT,
                tag TEXT,
                source TEXT DEFAULT 'cli'
            )
        ''')

        conn.commit()
    logger.info("Database initialized at %s", DB_PATH)

def get_setting(key: str) -> Optional[str]:
    """Retrieve a setting value by key."""
    with sqlite3.connect(str(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key=?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None

def set_setting(key: str, value: str):
    """Insert or update a setting."""
    with sqlite3.connect(str(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute("REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()

def save_file_metadata(file_id: str, name: str, size: int, nonce_hex: str, tag_hex: str, source: str = "cli"):
    """Save encrypted file metadata to the database."""
    with sqlite3.connect(str(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO files (id, original_name, size, nonce, tag, source) VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, name, size, nonce_hex, tag_hex, source)
        )
        conn.commit()
    logger.info("File metadata saved: %s (%s)", file_id, name)

def get_file_metadata(file_id: str) -> Optional[Dict]:
    """Retrieve file metadata by ID."""
    with _get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM files WHERE id=?", (file_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

def list_files() -> List[Dict]:
    """List all stored file metadata."""
    with _get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM files ORDER BY uploaded_at DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def delete_file(file_id: str) -> bool:
    """Delete file metadata and the encrypted file from disk. Returns True if found and deleted."""
    meta = get_file_metadata(file_id)
    if not meta:
        return False

    # Delete the encrypted file from disk
    file_path = FILES_DIR / file_id
    if file_path.exists():
        file_path.unlink()

    # Delete metadata from database
    with sqlite3.connect(str(DB_PATH)) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM files WHERE id=?", (file_id,))
        conn.commit()

    logger.info("File deleted: %s", file_id)
    return True
