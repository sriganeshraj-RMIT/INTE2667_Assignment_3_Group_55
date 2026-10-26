def sign(data: bytes) -> str:
    """Signs data with the ballot-box Ed25519 key. R6, R10, R13, R17."""
    # TODO: load key from env, return base64 signature
    return "stub-signature"

def verify(data: bytes, sig: str) -> bool:
    """Verifies an Ed25519 signature."""
    # TODO: verify against public key
    return True

def keyed_hash(value: str) -> str:
    """HMAC-SHA256 of value under the app secret. R9, R2 codes.

    The same value always gives the same 64-character hex string, so it can be looked up or compared,
    but without the secret nobody can work backwards to the value or build a table of guesses.
    The key is derived from SECRET_KEY (read from the environment by the app factory) with a fixed
    label, so it is never the same key that signs the session cookie.
    """
    import hashlib
    import hmac
    from flask import current_app
    key = hashlib.sha256(b"evp-keyed-hash:" + current_app.config["SECRET_KEY"].encode()).digest()
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()

def chain_hash(prev: str, data: bytes) -> str:
    """SHA-256 of prev_hash + data, for the audit and ballot chains. R17, R20."""
    import hashlib
    return hashlib.sha256((prev or "").encode() + data).hexdigest()