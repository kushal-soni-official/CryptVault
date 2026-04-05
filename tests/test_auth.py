import os
from cryptvault.core.auth import (
    generate_totp_secret, verify_totp,
    create_password_check, verify_password_check
)


# ── Auth Tests ─────────────────────────────────────────────────

def test_totp_generation():
    """Test that TOTP secret is generated as a valid base32 string."""
    secret = generate_totp_secret()
    assert len(secret) > 0
    assert secret.isalnum()


def test_password_check_correct():
    """Test that password verification succeeds with the correct password."""
    password = "MySecurePassword123"
    salt = os.urandom(16)
    check = create_password_check(password, salt)
    assert verify_password_check(password, salt, check) is True


def test_password_check_wrong():
    """Test that password verification fails with the wrong password."""
    password = "MySecurePassword123"
    salt = os.urandom(16)
    check = create_password_check(password, salt)
    assert verify_password_check("WrongPassword", salt, check) is False


def test_password_check_wrong_salt():
    """Test that password verification fails with the wrong salt."""
    password = "MySecurePassword123"
    salt = os.urandom(16)
    wrong_salt = os.urandom(16)
    check = create_password_check(password, salt)
    assert verify_password_check(password, wrong_salt, check) is False
