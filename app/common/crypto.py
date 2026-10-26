def sign(data: bytes) -> str:
    """Signs data with the ballot-box Ed25519 key. R6, R10, R13, R17."""
    # TODO: load key from env, return base64 signature
    return "stub-signature"

def verify(data: bytes, sig: str) -> bool:
    """Verifies an Ed25519 signature."""
    # TODO: verify against public key
    return True

def keyed_hash(value: str) -> str:
    """HMAC-SHA256 of value under the app secret. R9, R2 codes."""
    # TODO: use HMAC with SECRET_KEY from env
    return "stub-hash"

def chain_hash(prev: str, data: bytes) -> str:
    """SHA-256 of prev_hash + data, for the audit and ballot chains. R17, R20."""
    import hashlib
    return hashlib.sha256((prev or "").encode() + data).hexdigest()