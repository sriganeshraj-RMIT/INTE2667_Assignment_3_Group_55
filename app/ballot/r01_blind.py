"""R1 - the blind-signature maths (RSA), in one small file so it can be explained line by line.

The issuer has an RSA key: public (n, e), private d.

  voter    m = H(election_id, token)            the pass the voter wants signed (kept secret)
  voter    blinded = m * r^e mod n              r is random, so `blinded` looks random too
  issuer   s' = blinded^d mod n                 signs WITHOUT seeing m
  voter    s = s' * r^-1 mod n                  = m^d mod n: a normal signature on m
  checker  s^e mod n == H(election_id, token)   valid, but the issuer never saw this token

So the issuer knows WHO got a pass, the checker knows WHICH pass was used, and nothing links the two.
This is "textbook" blind RSA with a full-domain hash, kept simple for the prototype. A production system
would use the standardised version, RFC 9474 (RSA blind signatures).
"""
import hashlib
import secrets
from math import gcd

E = 65537
KEY_BITS = 2048


def full_domain_hash(election_id: str, token: bytes, n: int) -> int:
    """Hashes (election, token) to a number as wide as n. Tying in the election stops a pass being reused
    in another election."""
    width = (n.bit_length() + 7) // 8
    seed = election_id.encode() + b"|" + token
    out, counter = b"", 0
    while len(out) < width:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return int.from_bytes(out[:width], "big") % n


def blind(m: int, n: int, e: int = E):
    """VOTER: hides m. Returns (blinded, r); keep r to unblind."""
    while True:
        r = secrets.randbelow(n - 2) + 2
        if gcd(r, n) == 1:
            return (m * pow(r, e, n)) % n, r


def sign_blinded(blinded: int, d: int, n: int) -> int:
    """ISSUER: signs what it is given. It cannot see the pass inside."""
    return pow(blinded, d, n)


def unblind(blind_signature: int, r: int, n: int) -> int:
    """VOTER: removes r, leaving a normal signature on m."""
    return (blind_signature * pow(r, -1, n)) % n


def verify(m: int, signature: int, n: int, e: int = E) -> bool:
    """CHECKER: needs only the public key."""
    return 0 < signature < n and pow(signature, e, n) == m
