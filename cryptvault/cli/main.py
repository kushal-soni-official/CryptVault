import click
import os
import uuid
from typing import Optional
from pathlib import Path

from cryptvault.core.models import init_db, get_setting, set_setting, save_file_metadata, get_file_metadata, list_files, FILES_DIR
from cryptvault.core.auth import generate_totp_secret, get_totp_uri, generate_qr_code, verify_totp
from cryptvault.core.encryption import encrypt_file, decrypt_file
from cryptvault.integrations.nmap_integration import scan_target
from cryptvault.integrations.cve_integration import check_cve
from cryptvault.integrations.scapy_integration import analyze_pcap
from cryptvault.cli.utils import print_success, print_error, print_warning, print_info

@click.group()
def main():
    """CryptVault - Zero-Knowledge Encrypted File Storage"""
    pass

@main.command()
def init():
    """Initialize a new vault."""
    init_db()
    if get_setting("vault_initialized") == "true":
        print_warning("Vault is already initialized!")
        return

    password = click.prompt("Enter a strong master password", hide_input=True, confirmation_prompt=True)
    
    # Generate cryptographic salt for Argon2id
    salt = os.urandom(16)
    set_setting("kdf_salt", salt.hex())
    
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
    if get_setting("vault_initialized") != "true":
        print_error("Vault not initialized. Run 'cryptvault init' first.")
        return None
        
    password = click.prompt("Enter master password", hide_input=True)
    totp_code = click.prompt("Enter 2FA code")
    
    secret = get_setting("totp_secret")
    if not verify_totp(secret, totp_code):
        print_error("Invalid 2FA code.")
        return None
        
    salt_hex = get_setting("kdf_salt")
    salt = bytes.fromhex(salt_hex)
    return password, salt

@main.command()
@click.argument('filepath', type=click.Path(exists=True))
def store(filepath):
    """Encrypt and store a file into the vault."""
    auth_data = require_auth()
    if not auth_data: return
    password, salt = auth_data
    
    file_id = str(uuid.uuid4())
    input_path = Path(filepath)
    output_path = FILES_DIR / file_id
    
    print_info(f"Encrypting {input_path.name}...")
    try:
        nonce, tag = encrypt_file(str(input_path), str(output_path), password, salt)
        save_file_metadata(file_id, input_path.name, input_path.stat().st_size, nonce.hex(), tag.hex())
        print_success(f"File encrypted and stored securely! ID: {file_id}")
    except Exception as e:
        print_error(f"Failed to encrypt file: {str(e)}")

@main.command()
@click.argument('fileid')
def retrieve(fileid):
    """Decrypt and download a file from the vault."""
    auth_data = require_auth()
    if not auth_data: return
    password, salt = auth_data
    
    meta = get_file_metadata(fileid)
    if not meta:
        print_error("File ID not found.")
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
        print_error(f"Error during decryption: {str(e)}")

@main.command()
def list():
    """List all stored files metadata (no decryption required)."""
    if get_setting("vault_initialized") != "true":
        print_error("Vault not initialized.")
        return
        
    files = list_files()
    if not files:
        print_info("Vault is empty.")
        return
        
    click.echo(f"{'ID':<40} {'Name':<30} {'Size (bytes)':<15}")
    click.echo("-" * 85)
    for f in files:
        click.echo(f"{f['id']:<40} {f['original_name']:<30} {f['size']:<15}")

@main.command(name="scan-network")
@click.argument("target")
def scan_network_cmd(target):
    """Run an Nmap scan against a target."""
    print_info(f"Scanning target: {target}")
    results = scan_target(target)
    import json
    click.echo(json.dumps(results, indent=2))

@main.command(name="cve-check")
@click.argument("software")
@click.argument("version")
def cve_check_cmd(software, version):
    """Check NIST NVD for known vulnerabilities."""
    print_info(f"Checking NVD for {software} {version}...")
    results = check_cve(software, version)
    import json
    click.echo(json.dumps(results, indent=2))

@main.command(name="packet-analyze")
@click.argument("pcap_file", type=click.Path(exists=True))
def packet_analyze_cmd(pcap_file):
    """Analyze a PCAP file for anomalies."""
    print_info(f"Analyzing {pcap_file}...")
    results = analyze_pcap(pcap_file)
    import json
    click.echo(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
