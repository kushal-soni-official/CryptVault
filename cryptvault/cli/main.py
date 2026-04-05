import click
import json
import os
import uuid
import logging
from typing import Optional
from pathlib import Path

from cryptvault.core.models import (
    init_db, get_setting, set_setting, save_file_metadata,
    get_file_metadata, list_files, delete_file, FILES_DIR
)
from cryptvault.core.auth import (
    generate_totp_secret, get_totp_uri, generate_qr_code,
    verify_totp, create_password_check, verify_password_check
)
from cryptvault.core.encryption import encrypt_file, decrypt_file
from cryptvault.cli.utils import print_success, print_error, print_warning, print_info

logger = logging.getLogger(__name__)

@click.group()
def main():
    """CryptVault — Zero-Trust Encrypted File Storage & Security Toolkit"""
    # Configure basic logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler()]
    )

@main.command()
def init():
    """Initialize a new vault with master password and 2FA."""
    init_db()
    if get_setting("vault_initialized") == "true":
        print_warning("Vault is already initialized!")
        return

    password = click.prompt("Enter a strong master password", hide_input=True, confirmation_prompt=True)

    # Generate cryptographic salt for Argon2id
    salt = os.urandom(16)
    set_setting("kdf_salt", salt.hex())

    # Store password verification hash (NOT the password itself)
    pw_check = create_password_check(password, salt)
    set_setting("password_check", pw_check)

    # 2FA Setup
    totp_secret = generate_totp_secret()
    set_setting("totp_secret", totp_secret)

    uri = get_totp_uri(totp_secret)
    print_info("Scan this QR code with Google Authenticator or Authy:")
    print(generate_qr_code(uri))
    print_info(f"Or enter this code manually: {totp_secret}")

    totp_code = click.prompt("Enter code from your app to verify")
    if verify_totp(totp_secret, totp_code):
        set_setting("vault_initialized", "true")
        print_success("Vault initialized successfully!")
    else:
        print_error("Invalid code. Initialization failed.")

def require_auth() -> Optional[tuple[str, bytes]]:
    """Prompt for master password + 2FA and verify both. Returns (password, salt) or None."""
    if get_setting("vault_initialized") != "true":
        print_error("Vault not initialized. Run 'cryptvault init' first.")
        return None

    password = click.prompt("Enter master password", hide_input=True)

    # Verify master password before proceeding
    salt_hex = get_setting("kdf_salt")
    salt = bytes.fromhex(salt_hex)
    stored_check = get_setting("password_check")

    if stored_check and not verify_password_check(password, salt, stored_check):
        print_error("Invalid master password.")
        return None

    totp_code = click.prompt("Enter 2FA code")
    secret = get_setting("totp_secret")
    if not verify_totp(secret, totp_code):
        print_error("Invalid 2FA code.")
        return None

    return password, salt

@main.command()
@click.argument('filepath', type=click.Path(exists=True))
def store(filepath):
    """Encrypt and store a file into the vault."""
    auth_data = require_auth()
    if not auth_data:
        return
    password, salt = auth_data

    file_id = str(uuid.uuid4())
    input_path = Path(filepath)
    output_path = FILES_DIR / file_id

    print_info(f"Encrypting {input_path.name}...")
    try:
        nonce, tag = encrypt_file(str(input_path), str(output_path), password, salt)
        save_file_metadata(file_id, input_path.name, input_path.stat().st_size, nonce.hex(), tag.hex(), source="cli")
        print_success(f"File encrypted and stored securely! ID: {file_id}")
    except Exception as e:
        print_error(f"Failed to encrypt file: {e}")
        logger.exception("Encryption failed for %s", filepath)

@main.command()
@click.argument('fileid')
def retrieve(fileid):
    """Decrypt and download a file from the vault."""
    auth_data = require_auth()
    if not auth_data:
        return
    password, salt = auth_data

    meta = get_file_metadata(fileid)
    if not meta:
        print_error("File ID not found.")
        return

    if meta.get("source") == "web":
        print_error("This file was encrypted via the Web UI (PBKDF2). It cannot be decrypted via CLI (Argon2id).")
        print_info("Please use the Web UI to download and decrypt this file.")
        return

    output_path = Path.cwd() / meta['original_name']
    input_path = FILES_DIR / fileid

    print_info(f"Decrypting {meta['original_name']}...")
    try:
        success = decrypt_file(
            str(input_path),
            str(output_path),
            password,
            salt,
            bytes.fromhex(meta['nonce']),
            bytes.fromhex(meta['tag'])
        )
        if success:
            print_success(f"File successfully decrypted to {output_path}")
        else:
            print_error("Decryption failed. Invalid password or corrupted data.")
    except Exception as e:
        print_error(f"Error during decryption: {e}")
        logger.exception("Decryption failed for %s", fileid)

@main.command(name="list")
def list_cmd():
    """List all stored files metadata (no decryption required)."""
    if get_setting("vault_initialized") != "true":
        print_error("Vault not initialized.")
        return

    files = list_files()
    if not files:
        print_info("Vault is empty.")
        return

    click.echo(f"{'ID':<40} {'Name':<30} {'Size (bytes)':<15} {'Source':<8}")
    click.echo("-" * 95)
    for f in files:
        source = f.get('source', 'cli')
        click.echo(f"{f['id']:<40} {f['original_name']:<30} {f['size']:<15} {source:<8}")

@main.command()
@click.argument('fileid')
def delete(fileid):
    """Delete a file from the vault permanently."""
    auth_data = require_auth()
    if not auth_data:
        return

    meta = get_file_metadata(fileid)
    if not meta:
        print_error("File ID not found.")
        return

    if not click.confirm(f"Permanently delete '{meta['original_name']}'? This cannot be undone"):
        print_info("Cancelled.")
        return

    if delete_file(fileid):
        print_success(f"File '{meta['original_name']}' deleted permanently.")
    else:
        print_error("Failed to delete file.")

if __name__ == "__main__":
    main()
