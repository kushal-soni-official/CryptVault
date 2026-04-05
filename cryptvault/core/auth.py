import pyotp
import qrcode
import io

def generate_totp_secret() -> str:
    """Generates a random base32 string for TOTP."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, name: str = "CryptVault") -> str:
    """Generates the provisioning URI for Google Authenticator / Authy."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=name, issuer_name="CryptVault")

def generate_qr_code(uri: str) -> str:
    """Generate ASCII representation of QR code for CLI."""
    qr = qrcode.QRCode()
    qr.add_data(uri)
    f = io.StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    return f.read()

def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
