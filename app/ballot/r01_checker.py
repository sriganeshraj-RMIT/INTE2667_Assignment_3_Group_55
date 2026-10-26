"""R1 - CHECKER: accepts a sealed ballot from anyone holding a valid, unused voting pass.

  POST /ballot/<election_id>/cast   NO sign-in on purpose
       body {"token": hex, "signature": hex, "sealed_ballot": text}

The checker never asks who is voting. It does not import current_user, reads only the PUBLIC key (n, e),
records a used pass as a SHA-256 hash with the election and nothing else, and hands the ballot to R4's
store_ballot (random id, no time, shuffled batch), then returns R6's signed receipt. It writes no audit entry for a good ballot, because one
entry per ballot would put a time next to each vote (R4 logs one entry per batch instead).

Order matters: the pass is marked used FIRST (the database refuses a second use), then the ballot is stored,
then both are committed. If storing fails (for example polls have closed) the pass is not used up.

In the real deployment the checker runs as a separate service on its own address, so the voter's sign-in
cookie is never even sent to it.
"""
import hashlib

from flask import jsonify, request
from sqlalchemy.exc import IntegrityError

from . import bp
from .r01_blind import full_domain_hash, verify
from .r01_models import PassKey, SpentPass
from .r04_ballot_box import BallotBoxError, store_ballot
from .r06_receipt import make_receipt
from app.common.audit import audit
from app.common.security import csrf_exempt
from app.common.validate import validate
from app.election.r10_lock import ElectionError
from app.extensions import db

CAST_SCHEMA = {
    "token":         {"type": str, "pattern": r"[0-9a-f]{64}", "required": True},
    "signature":     {"type": str, "pattern": r"[0-9a-f]{1,1024}", "max_length": 1024, "required": True},
    "sealed_ballot": {"type": str, "max_length": 20000, "required": True, "allow_markup": True},
}


class CastError(Exception):
    """A refusal that is turned into the team's error JSON: {"error": CODE, "message": text}."""

    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


def _public_key(election_id):
    """Only n and e. The checker never touches the private key column."""
    row = db.session.query(PassKey.n_hex, PassKey.e).filter_by(election_id=election_id).first()
    return None if row is None else (int(row[0], 16), row[1])


def cast_ballot(election_id, token_hex, signature_hex, sealed):
    """Checks the pass, uses it up, stores the ballot. Returns the ballot hash (for R6's confirmation code)."""
    key = _public_key(election_id)
    token = bytes.fromhex(token_hex)
    if key is None or not verify(full_domain_hash(election_id, token, key[0]), int(signature_hex, 16), *key):
        audit("BALLOT_PASS_REJECTED", actor_id="anonymous", details={"election_id": election_id})
        raise CastError("PASS_INVALID", "This voting pass is not valid for this election.", 403)

    db.session.add(SpentPass(token_hash=hashlib.sha256(token).hexdigest(), election_id=election_id))
    try:
        db.session.flush()                       # the primary key refuses a pass that was already used
    except IntegrityError:
        db.session.rollback()
        audit("BALLOT_PASS_REUSE_BLOCKED", actor_id="anonymous", details={"election_id": election_id})
        raise CastError("PASS_ALREADY_USED", "This voting pass has already been used.", 409)

    try:
        ballot_hash = store_ballot(election_id, sealed)       # R4: random id, no time, shuffled batch
    except (BallotBoxError, ElectionError) as e:
        db.session.rollback()                    # the pass is NOT used up, so the voter can try again
        raise CastError(e.code, e.message, e.status)
    except Exception:
        db.session.rollback()
        raise
    db.session.commit()
    return ballot_hash


@bp.post("/<election_id>/cast")                  # final URL: /ballot/<election_id>/cast (no sign-in, on purpose)
@csrf_exempt            # no sign-in here, so a CSRF token adds nothing and would make the device send a session cookie
def ballot_cast(election_id):
    data = validate(CAST_SCHEMA, request.get_json(silent=True))
    try:
        ballot_hash = cast_ballot(election_id, data["token"], data["signature"], data["sealed_ballot"])
    except CastError as e:
        return error_response(e)
    # R6: the voter gets a signed confirmation code built from the SEALED ballot, never from their choices
    return jsonify({"accepted": True, **make_receipt(election_id, ballot_hash)}), 201
