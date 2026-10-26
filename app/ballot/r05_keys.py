"""R5 - The key ceremony and the public key.

A custodian runs the ceremony once for an election, BEFORE polls open. It makes the election key pair and prints
5 shares. The shares are shown once, in that response only. They are never stored and never logged: the
custodian hands them to five different officials. Voters' devices fetch the public key and lock their ballots with it.
"""
from flask import jsonify
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from . import bp
from app.common.audit import audit
from app.common.auth import current_user, login_required, role_required
from app.extensions import db
from .r05_crypto import SHARE_COUNT, THRESHOLD, make_election_key
from .r05_models import ElectionKey

CEREMONY_ROLES = ("custodian",)


class CeremonyError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def run_ceremony(user, election_id):
    if not user or user.get("role") not in CEREMONY_ROLES:
        audit("BALLOT_KEY_CEREMONY_REFUSED", actor_id=(user or {}).get("id", "anonymous"),
              details={"election_id": election_id, "role": (user or {}).get("role")})
        raise CeremonyError("FORBIDDEN", "Only a custodian can run the key ceremony.", 403)
    status = db.session.execute(text("SELECT status FROM elections WHERE id = :eid"), {"eid": election_id}).scalar()
    if status is None:
        raise CeremonyError("NOT_FOUND", "No such election.", 404)
    if status not in ("DRAFT", "APPROVED"):
        raise CeremonyError("ELECTION_ALREADY_OPEN", "The key must be made before the polls open.", 409)
    if db.session.get(ElectionKey, election_id) is not None:
        raise CeremonyError("KEY_EXISTS", "This election already has a key.", 409)
    public_pem, locked_private_key, shares = make_election_key()
    db.session.add(ElectionKey(election_id=election_id, public_key_pem=public_pem,
                               locked_private_key=locked_private_key, threshold=THRESHOLD,
                               share_count=SHARE_COUNT, created_by=user["id"]))
    try:
        db.session.commit()
    except IntegrityError:                       # two ceremonies at the same moment: the database lets one through
        db.session.rollback()
        raise CeremonyError("KEY_EXISTS", "This election already has a key.", 409)
    audit("BALLOT_KEY_CEREMONY_DONE", actor_id=user["id"],          # note: the shares are NOT in the log
          details={"election_id": election_id, "shares_made": SHARE_COUNT, "needed_to_open": THRESHOLD})
    return public_pem, shares


# ----------------------------------------------------------------- routes
@bp.post("/<election_id>/ceremony")              # final URL: /ballot/<election_id>/ceremony
@login_required
@role_required("custodian")
def ceremony(election_id):
    try:
        public_pem, shares = run_ceremony(current_user(), election_id)
    except CeremonyError as e:
        return jsonify({"error": e.code, "message": e.message}), e.status
    response = jsonify({"election_id": election_id, "public_key_pem": public_pem, "shares": shares,
                        "needed_to_open": THRESHOLD,
                        "note": "Give each share to a different official. They are not stored and cannot be shown again."})
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.get("/<election_id>/public-key")             # public on purpose: voters' devices need it to lock ballots
def public_key(election_id):
    key = db.session.get(ElectionKey, election_id)
    if key is None:
        return jsonify({"error": "NOT_FOUND", "message": "No key has been made for this election yet."}), 404
    return jsonify({"election_id": election_id, "public_key_pem": key.public_key_pem})
