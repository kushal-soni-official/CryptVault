import hmac
import hashlib
import pyotp
import qrcode
import io

# Constant used for master password verification (not the password itself)
_VERIFY_CONSTANT = b"cryptvault-password-verification-v1"

def generate_totp_secret() -> str:
    """Generates a random base32 string for TOTP."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, name: str = "CryptVault") -> str:
    """Generates the provisioning URI for Google Authenticator / Authy."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=name, issuer_name="CryptVault")

def generate_qr_code(uri: str) -> str:
    """Generate ASCII representation of QR code for CLI display."""
    qr = qrcode.QRCode()
    qr.add_data(uri)
    f = io.StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    return f.read()

def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code with a ±1 window for clock drift tolerance."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def create_password_check(password: str, salt: bytes) -> str:
    """
    Create an HMAC-based verification hash for the master password.
    This allows verifying the password is correct before attempting decryption.
    The verification hash is NOT the encryption key — it's derived separately.
    """
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=100000)
    check = hmac.new(key, _VERIFY_CONSTANT, hashlib.sha256).hexdigest()
    return check

def verify_password_check(password: str, salt: bytes, stored_check: str) -> bool:
    """Verify a master password against the stored verification hash."""
    computed = create_password_check(password, salt)
    return hmac.compare_digest(computed, stored_check)
