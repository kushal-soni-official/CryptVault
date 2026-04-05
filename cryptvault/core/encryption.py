import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key using Argon2id."""
    # RFC 9106 recommended parameters (memory cost 19MB, 2 iterations, parallelism 1)
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=2,
        lanes=1,
        memory_cost=19456, # 19 * 1024
    )
    return kdf.derive(password.encode())

def encrypt_file(input_filepath: str, output_filepath: str, password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts a file and returns (nonce, tag).
    AESGCM normally requires the whole data in memory for single-pass authentication.
    For simplicity in this scale (and CLI), we read the file entirely if it's small,
    or we can stream it using different primitives, but AESGCM API from cryptography
    doesn't natively stream cleanly without chunks. We'll use the one-shot API.
    """
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    
    with open(input_filepath, "rb") as f:
        data = f.read()
        
    encrypted_data = aesgcm.encrypt(nonce, data, None)
    
    # AESGCM combines ciphertext + tag. Tag is the last 16 bytes.
    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[:-16]
    
    with open(output_filepath, "wb") as f:
        f.write(ciphertext)
        
    return nonce, tag

def decrypt_file(input_filepath: str, output_filepath: str, password: str, salt: bytes, nonce: bytes, tag: bytes) -> bool:
    """Decrypts a file that was encrypted using encrypt_file."""
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    
    with open(input_filepath, "rb") as f:
        ciphertext = f.read()
        
    # Reassemble to decrypt safely
    try:
        data = aesgcm.decrypt(nonce, ciphertext + tag, None)
        with open(output_filepath, "wb") as f:
            f.write(data)
        return True
    except InvalidTag:
        return False
