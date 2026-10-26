"""R5 - Sealed ballots: the locks (no web code and no database in this file).

Three ideas, in plain words:
  1. A ballot is LOCKED ON THE VOTER'S OWN DEVICE with the election PUBLIC key, so nobody on the server can read it.
     (A fresh random AES key locks the ballot; the election public key locks that AES key.)
  2. The matching election PRIVATE key is never stored in the clear. It is locked under a random master key.
  3. The master key is split into 5 SHARES (Shamir secret sharing). Any 3 shares rebuild it; 2 learn nothing.
     So three officials must work together before a single ballot can be read.
"""
import base64
import json
import os
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

THRESHOLD = 3           # shares needed to open the ballot box
SHARE_COUNT = 5         # shares handed out
PRIME = 2 ** 521 - 1    # a prime much bigger than the 256-bit master key
SHARE_PATTERN = re.compile(r"^[1-9][0-9]?-[0-9a-f]{1,132}$")      # a share looks like  "2-1f3a9c..."
_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_WRAP_LABEL = b"election-private-key"


class BadShares(Exception):
    """Not enough shares, a mistyped share, or shares that do not belong together."""


def _b64e(data):
    return base64.b64encode(data).decode()


def _b64d(text):
    if not isinstance(text, str):
        raise ValueError("expected text")
    return base64.b64decode(text.encode(), validate=True)


# ------------------------------------------------------------ Shamir (3 of 5)
def split_secret(secret, k=THRESHOLD, n=SHARE_COUNT):
    """Hide the secret in a random polynomial of degree k-1; a share is one point on it."""
    value = int.from_bytes(secret, "big")
    coefficients = [value] + [secrets.randbelow(PRIME) for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        for c in reversed(coefficients):
            y = (y * x + c) % PRIME
        shares.append(f"{x}-{y:x}")
    return shares


def combine_shares(shares):
    """Rebuild the secret from at least THRESHOLD different shares (Lagrange interpolation at x = 0)."""
    points = {}
    for share in shares or []:
        if not isinstance(share, str) or not SHARE_PATTERN.match(share.strip()):
            raise BadShares("A share is not in the expected format.")
        x_text, y_text = share.strip().split("-")
        x, y = int(x_text), int(y_text, 16)
        if points.setdefault(x, y) != y:
            raise BadShares("Two different shares claim the same position.")
    if len(points) < THRESHOLD:
        raise BadShares(f"At least {THRESHOLD} different shares are needed.")
    total = 0
    for xi, yi in points.items():
        numerator, denominator = 1, 1
        for xj in points:
            if xj != xi:
                numerator = (numerator * -xj) % PRIME
                denominator = (denominator * (xi - xj)) % PRIME
        total = (total + yi * numerator * pow(denominator, -1, PRIME)) % PRIME
    try:
        return total.to_bytes(32, "big")
    except OverflowError:
        raise BadShares("These shares do not fit together.")


# ------------------------------------------------------------ the election key
def make_election_key():
    """The key ceremony: returns (public key PEM, locked private key, the 5 shares). Shares are never stored."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
    master_key = secrets.token_bytes(32)
    nonce = os.urandom(12)
    locked_private_key = nonce + AESGCM(master_key).encrypt(nonce, pem, _WRAP_LABEL)
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return public_pem, _b64e(locked_private_key), split_secret(master_key)


def unlock_private_key(locked_private_key, shares):
    """Needs THRESHOLD correct shares. With wrong or too few shares the lock simply does not open."""
    master_key = combine_shares(shares)
    blob = _b64d(locked_private_key)
    try:
        pem = AESGCM(master_key).decrypt(blob[:12], blob[12:], _WRAP_LABEL)
    except InvalidTag:
        raise BadShares("The shares are wrong for this election.")
    return serialization.load_pem_private_key(pem, password=None)


# ---------------------------------------------------------------- one ballot
def seal_ballot(public_pem, election_id, ballot):
    """What the voter's device does. The election ID is bound in, so a ballot cannot be moved to another election."""
    public_key = serialization.load_pem_public_key(public_pem.encode())
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    locked = AESGCM(aes_key).encrypt(nonce, json.dumps(ballot, sort_keys=True).encode(), election_id.encode())
    return json.dumps({"v": 1, "ek": _b64e(public_key.encrypt(aes_key, _OAEP)), "n": _b64e(nonce), "c": _b64e(locked)})


def open_ballot(private_key, election_id, sealed):
    """Returns the ballot, or None if this one is damaged or was not sealed for this election.

    Anyone with a voting pass can submit anything, so ONE odd ballot must never be able to stop the count:
    whatever goes wrong with it, it simply comes back as None (R7 counts it as informal).
    """
    try:
        envelope = json.loads(sealed)
        aes_key = private_key.decrypt(_b64d(envelope["ek"]), _OAEP)
        plain = AESGCM(aes_key).decrypt(_b64d(envelope["n"]), _b64d(envelope["c"]), election_id.encode())
        ballot = json.loads(plain)
    except Exception:
        return None
    return ballot if isinstance(ballot, dict) else None
