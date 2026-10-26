"""R10 - Candidates, party order and polling times locked and signed before polls open.

How it works (one sentence each):
  1. While an election is DRAFT, candidates and times can be entered.
  2. A Commissioner's delegate LOCKS it (POST /election/<id>/lock, after MFA). The candidate list, party order
     and opening and closing times are written out in a fixed format, hashed (SHA-256) and signed (Ed25519).
  3. From then on the database refuses any change to those candidates or times (triggers in
     db/init/30_setA_r10_lock.sql), so nobody can change who is on the ballot.
  4. Status moves APPROVED -> OPEN -> CLOSED by the locked times, and never back.
  5. Ballot casting must call require_polls_open(election_id): it refuses outside the locked times and if the
     stored definition no longer matches its signature, so no votes can be added after polls close.
  6. Anyone can fetch GET /election/<id>/definition and check the signature with the public key.
"""
import hashlib
import json
from datetime import datetime

from flask import current_app, jsonify, request
from sqlalchemy import text

from . import bp
from app.auth.r14_models import now
from app.common.audit import audit
from app.common.auth import current_user, login_required, mfa_required, role_required
from app.common.crypto import public_key_b64, sign, verify
from app.extensions import db

LOCK_ROLES = ("delegate",)
MIN_CANDIDATES = 2


class ElectionError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


def _dt(value):
    """MySQL gives datetime objects, SQLite gives text; make both the same."""
    return datetime.fromisoformat(str(value)) if not isinstance(value, datetime) else value


def _election(election_id):
    row = db.session.execute(text(
        "SELECT id, name, division, state, opens_at, closes_at, status, definition_fp, definition_sig "
        "FROM elections WHERE id = :eid"), {"eid": election_id}).mappings().first()
    if row is None:
        raise ElectionError("NOT_FOUND", "No such election.", 404)
    return row


def build_definition(election):
    """The exact text that is signed: the election, its times and its candidates in ballot order."""
    candidates = db.session.execute(text(
        "SELECT id, name, party, ballot_pos FROM candidates WHERE election_id = :eid ORDER BY ballot_pos, id"),
        {"eid": election["id"]}).mappings().all()
    definition = {
        "election_id": election["id"], "name": election["name"],
        "division": election["division"], "state": election["state"],
        "opens_at": _dt(election["opens_at"]).strftime("%Y-%m-%dT%H:%M:%S"),
        "closes_at": _dt(election["closes_at"]).strftime("%Y-%m-%dT%H:%M:%S"),
        "candidates": [{"id": c["id"], "name": c["name"], "party": c["party"], "ballot_pos": c["ballot_pos"]}
                       for c in candidates],
    }
    return definition, json.dumps(definition, sort_keys=True, separators=(",", ":")).encode()


# ------------------------------------------------------------------ logic
def lock_election(user, election_id):
    if not user or user.get("role") not in LOCK_ROLES:
        audit("ELECTION_LOCK_REFUSED", actor_id=(user or {}).get("id", "anonymous"),
              details={"election_id": election_id, "role": (user or {}).get("role")})
        raise ElectionError("FORBIDDEN", "Only a Commissioner's delegate can lock an election.", 403)
    election = _election(election_id)
    if election["status"] != "DRAFT":
        raise ElectionError("ALREADY_LOCKED", "This election is already locked.", 409)
    if not _dt(election["opens_at"]) < _dt(election["closes_at"]):
        raise ElectionError("BAD_TIMES", "Polls must close after they open.", 400)
    if not now() < _dt(election["opens_at"]):
        raise ElectionError("TOO_LATE", "An election must be locked before its polls open.", 409)

    definition, canonical = build_definition(election)
    positions = sorted(c["ballot_pos"] for c in definition["candidates"])
    if len(positions) < MIN_CANDIDATES or positions != list(range(1, len(positions) + 1)):
        raise ElectionError("BAD_CANDIDATES", "Candidates must be numbered 1, 2, 3 ... with no gaps or repeats.", 400)

    fingerprint = hashlib.sha256(canonical).hexdigest()
    signature = sign(fingerprint.encode())
    result = db.session.execute(text(
        "UPDATE elections SET status = 'APPROVED', definition_fp = :fp, definition_sig = :sig "
        "WHERE id = :eid AND status = 'DRAFT'"), {"fp": fingerprint, "sig": signature, "eid": election_id})
    db.session.commit()
    if result.rowcount != 1:
        raise ElectionError("ALREADY_LOCKED", "This election is already locked.", 409)
    audit("ELECTION_DEFINITION_LOCKED", actor_id=user["id"],
          details={"election_id": election_id, "definition_fp": fingerprint,
                   "candidates": len(definition["candidates"])})
    return fingerprint


def check_definition(election_id):
    """Recomputes the definition from the database and checks it against the stored hash and signature."""
    election = _election(election_id)
    if not election["definition_fp"]:
        return {"locked": False, "valid": False}
    definition, canonical = build_definition(election)
    fingerprint = hashlib.sha256(canonical).hexdigest()
    valid = fingerprint == election["definition_fp"] and verify(fingerprint.encode(), election["definition_sig"])
    return {"locked": True, "valid": bool(valid), "definition": definition,
            "definition_fp": election["definition_fp"], "signature": election["definition_sig"]}


def refresh_status():
    """Moves locked elections to OPEN and CLOSED by their locked times. Never moves backwards."""
    t = now().strftime("%Y-%m-%d %H:%M:%S")
    db.session.execute(text("UPDATE elections SET status = 'OPEN' "
                            "WHERE status = 'APPROVED' AND opens_at <= :t AND closes_at > :t"), {"t": t})
    db.session.execute(text("UPDATE elections SET status = 'CLOSED' "
                            "WHERE status IN ('APPROVED', 'OPEN') AND closes_at <= :t"), {"t": t})
    db.session.commit()


def require_polls_open(election_id):
    """FOR BALLOT CASTING (Srikanth): call this before accepting a ballot. Raises ElectionError if not allowed."""
    refresh_status()
    election = _election(election_id)
    if election["status"] != "OPEN":
        raise ElectionError("POLLS_NOT_OPEN", "Voting is not open for this election.", 409)
    if not check_definition(election_id)["valid"]:
        audit("ELECTION_DEFINITION_TAMPERED", actor_id="system", details={"election_id": election_id})
        raise ElectionError("DEFINITION_TAMPERED", "The ballot does not match the signed version. Voting is stopped.", 409)


@bp.before_app_request
def _keep_status_current():
    """Before any election or ballot request, bring the status in line with the locked times."""
    clock = current_app.config.get("ELECTION_CLOCK")
    if clock is None:
        clock = not current_app.config.get("TESTING", False)
    if clock and request.blueprint in ("election", "ballot"):
        refresh_status()


# ----------------------------------------------------------------- routes
@bp.post("/<election_id>/lock")                  # final URL: /election/<election_id>/lock
@login_required
@role_required(*LOCK_ROLES)
@mfa_required
def election_lock(election_id):
    try:
        fingerprint = lock_election(current_user(), election_id)
    except ElectionError as e:
        return error_response(e)
    return jsonify({"status": "APPROVED", "definition_fp": fingerprint})


@bp.get("/<election_id>/definition")             # public on purpose: anyone can check the signed ballot
def election_definition(election_id):
    try:
        result = check_definition(election_id)
    except ElectionError as e:
        return error_response(e)
    if not result["locked"]:
        return error_response(ElectionError("NOT_LOCKED", "This election has not been locked yet.", 404))
    return jsonify({**result, "public_key": public_key_b64()})
