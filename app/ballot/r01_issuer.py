"""R1 - ISSUER: gives a signed-in voter a voting pass with no name on it.

  GET  /ballot/<election_id>/pass-key   public key (n, e) the voter's device blinds with
  POST /ballot/<election_id>/pass       voter + MFA, body {"blinded": hex}
                                        -> marks the voter off (R3) AND blind-signs, in ONE transaction

The issuer proves who the voter is (sign-in + MFA, and R3's checks) but only ever sees a blinded number, so it
cannot recognise the pass when it is used. The private key never leaves this file; the checker (r01_checker.py)
reads only n and e.
"""
import base64
import hashlib
from math import gcd

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import current_app, jsonify, request
from sqlalchemy.exc import IntegrityError

from . import bp
from .r01_blind import E, KEY_BITS, sign_blinded
from .r01_models import PassKey
from .r03_register import RegisterError, lookup_election, mark_off
from app.auth.r14_models import now
from app.common.auth import current_user, login_required, mfa_required, role_required
from app.common.validate import validate
from app.extensions import db

ISSUE_SCHEMA = {"blinded": {"type": str, "pattern": r"[0-9a-f]{1,1024}", "max_length": 1024, "required": True}}


class PassError(Exception):
    """A refusal that is turned into the team's error JSON: {"error": CODE, "message": text}."""

    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


# ------------------------------------------------------------------ the election's key
def _fernet():
    key = hashlib.sha256(b"r01-pass-key:" + current_app.config["SECRET_KEY"].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _key_row(election_id):
    """The election's key, made the first time anyone asks for it."""
    row = db.session.get(PassKey, election_id)
    if row is not None:
        return row
    if lookup_election(election_id) is None:
        raise PassError("NOT_FOUND", "No such election.", 404)
    private = rsa.generate_private_key(public_exponent=E, key_size=KEY_BITS)
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    row = PassKey(election_id=election_id, n_hex=format(private.public_key().public_numbers().n, "x"),
                  e=E, private_enc=_fernet().encrypt(pem).decode(), created_at=now())
    db.session.add(row)
    try:
        db.session.commit()
    except IntegrityError:                       # another request made it at the same moment: use that one
        db.session.rollback()
        row = db.session.get(PassKey, election_id)
    return row


def public_key(election_id):
    row = _key_row(election_id)
    return {"n": row.n_hex, "e": row.e}


def _private_numbers(election_id):
    pem = _fernet().decrypt(_key_row(election_id).private_enc.encode())
    numbers = serialization.load_pem_private_key(pem, password=None).private_numbers()
    return numbers.d, numbers.public_numbers.n


# ------------------------------------------------------------------ issuing
def issue_voting_pass(user, election_id, blinded_hex):
    """Marks the voter off AND signs the blinded pass in one transaction (R3's mark_off with `then`).
    If signing fails the voter is NOT marked off. Returns the blind signature as hex."""
    if not user or user.get("role") != "voter":
        raise PassError("FORBIDDEN", "Only a voter can get a voting pass.", 403)
    d, n = _private_numbers(election_id)
    blinded = int(blinded_hex, 16)
    if not 1 < blinded < n or gcd(blinded, n) != 1:
        raise PassError("BAD_BLINDED_VALUE", "The blinded pass is not valid for this election's key.", 400)
    try:
        signed = mark_off(user["id"], election_id, "ONLINE", actor_id=user["id"],
                          then=lambda: sign_blinded(blinded, d, n))
    except RegisterError as e:                   # ALREADY_VOTED, POLLS_NOT_OPEN, WRONG_DIVISION, ...
        raise PassError(e.code, e.message, e.status)
    return format(signed, "x")                   # R3 has already audited BALLOT_VOTER_MARKED_OFF (channel ONLINE)


# ------------------------------------------------------------------ routes
@bp.get("/<election_id>/pass-key")               # final URL: /ballot/<election_id>/pass-key (public)
def pass_key(election_id):
    try:
        return jsonify(public_key(election_id))
    except PassError as e:
        return error_response(e)


@bp.post("/<election_id>/pass")                  # final URL: /ballot/<election_id>/pass
@login_required
@role_required("voter")
@mfa_required
def pass_issue(election_id):
    data = validate(ISSUE_SCHEMA, request.get_json(silent=True))
    try:
        signature = issue_voting_pass(current_user(), election_id, data["blinded"])
    except PassError as e:
        return error_response(e)
    return jsonify({"blind_signature": signature}), 201
