import base64
import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _private_key():
    """The platform's Ed25519 signing key.

    SIGNING_KEY in .env (32 random bytes, base64) is used if set. Otherwise, for local work, the key is
    derived from SECRET_KEY so it stays the same across restarts.
    """
    seed = os.environ.get("SIGNING_KEY")
    if seed:
        raw = base64.b64decode(seed)
    else:
        raw = hashlib.sha256(b"evp-signing-key:" + os.environ.get("SECRET_KEY", "dev-only").encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_b64() -> str:
    """The public half, so anyone outside the system can check signatures."""
    raw = _private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign(data: bytes) -> str:
    """Signs data with the platform Ed25519 key and returns the signature as base64. R13, R17."""
    return base64.b64encode(_private_key().sign(data)).decode()


def verify(data: bytes, sig: str) -> bool:
    """True only if sig is a valid Ed25519 signature of exactly these bytes."""
    try:
        raw_pub = base64.b64decode(public_key_b64())
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(base64.b64decode(sig or ""), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def keyed_hash(value: str) -> str:
    """HMAC-SHA256 of value under the app secret. R9, R2 codes."""
    # TODO: use HMAC with SECRET_KEY from env
    return "stub-hash"


def chain_hash(prev: str, data: bytes) -> str:
    """SHA-256 of prev_hash + data, for the audit and ballot chains. R17, R20."""
    return hashlib.sha256((prev or "").encode() + data).hexdigest()
