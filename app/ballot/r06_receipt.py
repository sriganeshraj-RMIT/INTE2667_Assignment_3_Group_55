"""R6 - Confirmation code.

After casting, the voter gets a receipt that proves "my sealed ballot reached the ballot box",
but says NOTHING about how they voted:
  * it is built from the SHA-256 hash of the SEALED ballot (R4's store_ballot() returns it), never from
    the choices. Because sealing uses fresh randomness (R5), two people who voted the same way still get
    different codes, so a receipt cannot be used to prove a vote to anyone (no vote buying or coercion);
  * it is signed with the platform's Ed25519 key, so a fake receipt is spotted;
  * it holds no voter id, name, time or IP, and nothing about it is stored: the ballot box already has the hash.

How the casting route uses it (after R1/R3 mark-off):
    receipt = make_receipt(election_id, store_ballot(election_id, sealed_ballot))
    return jsonify(receipt), 201

The voter can later check it, from any device and without signing in:
    POST /ballot/<election_id>/receipt/check   {"ballot_hash": "...", "signature": "..."}
    -> IN_BALLOT_BOX, WAITING (in the next R4 batch, not written yet), NOT_FOUND, or FORGED.
"""
import hashlib

from flask import jsonify, request
from sqlalchemy import text

from . import bp
from app.common.audit import audit
from app.common.crypto import public_key_b64, sign, verify
from app.common.validate import validate
from app.extensions import db, get_redis
from .r04_ballot_box import _pending_key

CHECK_SCHEMA = {
    "ballot_hash": {"type": str, "pattern": r"[0-9a-f]{64}", "required": True},
    "signature": {"type": str, "pattern": r"[A-Za-z0-9+/]{86}==", "required": True},     # Ed25519, base64
}


def receipt_message(election_id, ballot_hash):
    """What is signed. The election is included so a receipt cannot be moved to another election."""
    return f"EVP-RECEIPT:{election_id}:{ballot_hash}".encode()


def short_code(ballot_hash):
    """The part a person reads out or writes down, e.g. 3F9A-0C1B-77D2-E841."""
    head = ballot_hash[:16].upper()
    return "-".join(head[i:i + 4] for i in range(0, 16, 4))


def make_receipt(election_id, ballot_hash):
    return {
        "election_id": election_id,
        "confirmation_code": short_code(ballot_hash),
        "ballot_hash": ballot_hash,
        "signature": sign(receipt_message(election_id, ballot_hash)),
        "public_key": public_key_b64(),
        "note": "Keep this receipt. It proves your sealed ballot was received. It does not show how you voted.",
    }


def receipt_status(election_id, ballot_hash):
    with db.engines["ballot"].connect() as c:
        found = c.execute(text("SELECT 1 FROM ballots WHERE election_id = :eid AND ballot_hash = :h"),
                          {"eid": election_id, "h": ballot_hash}).first()
    if found:
        return "IN_BALLOT_BOX"
    for sealed in get_redis().lrange(_pending_key(election_id), 0, -1):         # at most one R4 batch
        raw = sealed if isinstance(sealed, (bytes, bytearray)) else str(sealed).encode()
        if hashlib.sha256(raw).hexdigest() == ballot_hash:
            return "WAITING"
    return "NOT_FOUND"


@bp.post("/<election_id>/receipt/check")         # public on purpose: a receipt is not linked to an account
def receipt_check(election_id):
    if not 0 < len(election_id) <= 36:
        return jsonify({"error": "BAD_ELECTION", "message": "Unknown election."}), 400
    data = validate(CHECK_SCHEMA, request.get_json(silent=True) or {})
    if not verify(receipt_message(election_id, data["ballot_hash"]), data["signature"]):
        audit("BALLOT_RECEIPT_FORGED", actor_id="anonymous", details={"election_id": election_id})
        return jsonify({"election_id": election_id, "signature_valid": False, "status": "FORGED",
                        "message": "This receipt was not issued by the voting platform."})
    return jsonify({"election_id": election_id, "signature_valid": True,
                    "confirmation_code": short_code(data["ballot_hash"]),
                    "status": receipt_status(election_id, data["ballot_hash"])})
