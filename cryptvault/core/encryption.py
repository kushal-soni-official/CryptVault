import os
import logging
from pathlib import Path
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

logger = logging.getLogger(__name__)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key using Argon2id (RFC 9106)."""
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=2,
        lanes=1,
        memory_cost=19456,  # 19 * 1024 KiB
    )
    return kdf.derive(password.encode())

def encrypt_file(input_filepath: str, output_filepath: str, password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts a file using AES-256-GCM and returns (nonce, tag).
    Reads the entire file into memory for single-pass authenticated encryption.
    """
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    with open(input_filepath, "rb") as f:
        data = f.read()

    encrypted_data = aesgcm.encrypt(nonce, data, None)

    # AESGCM output = ciphertext + 16-byte authentication tag
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[:-16]

    with open(output_filepath, "wb") as f:
        f.write(ciphertext)

    logger.info("File encrypted: %s -> %s", input_filepath, output_filepath)
    return nonce, tag

def decrypt_file(input_filepath: str, output_filepath: str, password: str, salt: bytes, nonce: bytes, tag: bytes) -> bool:
    """
    Decrypts a file that was encrypted using encrypt_file.
    Returns True on success, False on authentication failure.
    Cleans up partial output on failure.
    """
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    with open(input_filepath, "rb") as f:
        ciphertext = f.read()

    try:
        data = aesgcm.decrypt(nonce, ciphertext + tag, None)
        with open(output_filepath, "wb") as f:
            f.write(data)
        logger.info("File decrypted: %s -> %s", input_filepath, output_filepath)
        return True
    except InvalidTag:
        # Clean up any partial output file on failure
        output = Path(output_filepath)
        if output.exists():
            output.unlink()
        logger.warning("Decryption failed (invalid tag): %s", input_filepath)
        return False
