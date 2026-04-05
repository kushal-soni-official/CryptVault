import os
from pathlib import Path
from cryptvault.core.encryption import derive_key, encrypt_file, decrypt_file

def test_derive_key():
    password = "SuperSecretPassword123"
    salt = os.urandom(16)
    key = derive_key(password, salt)
    assert len(key) == 32

def test_encrypt_decrypt_file(tmp_path):
    password = "TestPassword123"
    salt = os.urandom(16)
    
    input_file = tmp_path / "test.txt"
    encrypted_file = tmp_path / "test.enc"
    decrypted_file = tmp_path / "test.dec"
    
    input_content = b"This is a test file for encryption."
    input_file.write_bytes(input_content)
    
    # Encrypt
    nonce, tag = encrypt_file(str(input_file), str(encrypted_file), password, salt)
    assert encrypted_file.exists()
    
    # Decrypt
    success = decrypt_file(str(encrypted_file), str(decrypted_file), password, salt, nonce, tag)
    assert success is True
    assert decrypted_file.read_bytes() == input_content

def test_decrypt_wrong_password(tmp_path):
    password = "TestPassword123"
    wrong_password = "WrongPassword123"
    salt = os.urandom(16)
    
    input_file = tmp_path / "test.txt"
    encrypted_file = tmp_path / "test.enc"
    decrypted_file = tmp_path / "test.dec"
    
    input_file.write_bytes(b"Secret")
    nonce, tag = encrypt_file(str(input_file), str(encrypted_file), password, salt)
    
    # Decrypt with wrong password
    success = decrypt_file(str(encrypted_file), str(decrypted_file), wrong_password, salt, nonce, tag)
    assert success is False
    assert not decrypted_file.exists()
