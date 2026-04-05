import sqlite3
import os
import json
from pathlib import Path
from typing import List, Dict, Optional

VAULT_DIR = Path.home() / ".cryptvault"
DB_PATH = VAULT_DIR / "vault.db"
FILES_DIR = VAULT_DIR / "files"

def init_db():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    
    # Track the basic settings, like auth salt
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    # Metadata for stored files
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id TEXT PRIMARY KEY,
            original_name TEXT,
            size INTEGER,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            nonce TEXT,
            tag TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

def get_setting(key: str) -> Optional[str]:
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def set_setting(key: str, value: str):
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    cursor.execute("REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def save_file_metadata(file_id: str, name: str, size: int, nonce_hex: str, tag_hex: str):
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO files (id, original_name, size, nonce, tag) VALUES (?, ?, ?, ?, ?)",
        (file_id, name, size, nonce_hex, tag_hex)
    )
    conn.commit()
    conn.close()

def get_file_metadata(file_id: str) -> Optional[Dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE id=?", (file_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def list_files() -> List[Dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
