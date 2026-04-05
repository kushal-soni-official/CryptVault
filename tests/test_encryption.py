import os
from pathlib import Path
from cryptvault.core.encryption import derive_key, encrypt_file, decrypt_file


def test_derive_key():
    """Test that Argon2id derives a 32-byte key."""
    password = "SuperSecretPassword123"
    salt = os.urandom(16)
    key = derive_key(password, salt)
    assert len(key) == 32


def test_derive_key_deterministic():
    """Same password + salt must produce the same key."""
    password = "TestPassword"
    salt = os.urandom(16)
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2


def test_derive_key_different_salt():
    """Different salts must produce different keys."""
    password = "TestPassword"
    key1 = derive_key(password, os.urandom(16))
    key2 = derive_key(password, os.urandom(16))
    assert key1 != key2


def test_encrypt_decrypt_file(tmp_path):
    """Test full encrypt → decrypt roundtrip."""
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
    assert len(nonce) == 12
    assert len(tag) == 16

    # Decrypt
    success = decrypt_file(str(encrypted_file), str(decrypted_file), password, salt, nonce, tag)
    assert success is True
    assert decrypted_file.read_bytes() == input_content


def test_encrypt_decrypt_empty_file(tmp_path):
    """Test roundtrip with an empty file."""
    password = "TestPassword123"
    salt = os.urandom(16)

    input_file = tmp_path / "empty.txt"
    encrypted_file = tmp_path / "empty.enc"
    decrypted_file = tmp_path / "empty.dec"

    input_file.write_bytes(b"")

    nonce, tag = encrypt_file(str(input_file), str(encrypted_file), password, salt)
    success = decrypt_file(str(encrypted_file), str(decrypted_file), password, salt, nonce, tag)
    assert success is True
    assert decrypted_file.read_bytes() == b""


def test_decrypt_wrong_password(tmp_path):
    """Wrong password must fail decryption and clean up output file."""
    password = "TestPassword123"
    wrong_password = "WrongPassword123"
    salt = os.urandom(16)

    input_file = tmp_path / "test.txt"
    encrypted_file = tmp_path / "test.enc"
    decrypted_file = tmp_path / "test.dec"

    input_file.write_bytes(b"Secret data")
    nonce, tag = encrypt_file(str(input_file), str(encrypted_file), password, salt)

    # Decrypt with wrong password — must return False
    success = decrypt_file(str(encrypted_file), str(decrypted_file), wrong_password, salt, nonce, tag)
    assert success is False
    # Output file should be cleaned up on failure
    assert not decrypted_file.exists()


def test_decrypt_wrong_salt(tmp_path):
    """Wrong salt must fail decryption."""
    password = "TestPassword123"
    salt = os.urandom(16)
    wrong_salt = os.urandom(16)

    input_file = tmp_path / "test.txt"
    encrypted_file = tmp_path / "test.enc"
    decrypted_file = tmp_path / "test.dec"

    input_file.write_bytes(b"Secret data")
    nonce, tag = encrypt_file(str(input_file), str(encrypted_file), password, salt)

    success = decrypt_file(str(encrypted_file), str(decrypted_file), password, wrong_salt, nonce, tag)
    assert success is False
