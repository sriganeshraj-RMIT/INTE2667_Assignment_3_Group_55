"""R13 - Signed results.

After the count (R7), a counting officer with live R14 access ("results") PUBLISHES the result. Publishing signs
the exact result text with sign() from app/common/crypto.py. Anyone can then read the result and check the
signature with verify(); if even one character of the result is changed, the check fails.

Reading a published result is public on purpose: outside groups (media, parties) must be able to check it.
"""
import json

from flask import jsonify
from sqlalchemy import update

from . import bp
from app.auth.r14_elevation import elevation_required
from app.auth.r14_models import now
from app.common.audit import audit
from app.common.auth import current_user, login_required, role_required
from app.common.crypto import sign, verify
from app.extensions import db
from .r07_count import canonical
from .r07_models import CountResult

PUBLISH_ROLES = ("counting_officer", "admin")


class ResultError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def publish_result(user, election_id):
    if not user or user.get("role") not in PUBLISH_ROLES:
        audit("ELECTION_RESULTS_REFUSED", actor_id=(user or {}).get("id", "anonymous"),
              details={"election_id": election_id, "role": (user or {}).get("role")})
        raise ResultError("FORBIDDEN", "Only a counting officer or an admin can publish results.", 403)
    row = (db.session.query(CountResult).filter_by(election_id=election_id)
           .order_by(CountResult.counted_at.desc()).first())
    if row is None:
        raise ResultError("NO_RESULT", "There is no counted result to publish yet.", 409)
    if row.published_at is not None:
        raise ResultError("ALREADY_PUBLISHED", "This result has already been published.", 409)
    signature = sign(row.payload_json.encode())
    # ONE update that only succeeds while the result is still unpublished, so two people publishing at the
    # same moment cannot both win.
    result = db.session.execute(
        update(CountResult).where(CountResult.id == row.id, CountResult.published_at.is_(None))
        .values(signature=signature, published_at=now()).execution_options(synchronize_session=False))
    db.session.commit()
    if result.rowcount != 1:
        raise ResultError("ALREADY_PUBLISHED", "This result has already been published.", 409)
    audit("ELECTION_RESULTS_PUBLISHED", actor_id=user["id"], details={"election_id": election_id, "result_id": row.id})
    return db.session.get(CountResult, row.id)


def published_result(election_id):
    row = (db.session.query(CountResult).filter(CountResult.election_id == election_id,
                                                CountResult.published_at.isnot(None))
           .order_by(CountResult.published_at.desc()).first())
    if row is None:
        raise ResultError("NOT_PUBLISHED", "No result has been published for this election.", 404)
    payload = json.loads(row.payload_json)
    return {"election_id": election_id, "result": payload, "signature": row.signature,
            "signature_valid": bool(verify(canonical(payload), row.signature))}


# ----------------------------------------------------------------- routes
@bp.post("/<election_id>/results/publish")       # final URL: /election/<election_id>/results/publish
@login_required
@role_required("counting_officer", "admin")
@elevation_required("results")
def results_publish(election_id):
    try:
        row = publish_result(current_user(), election_id)
    except ResultError as e:
        return jsonify({"error": e.code, "message": e.message}), e.status
    return jsonify({"result_id": row.id, "published_at": row.published_at.isoformat()})


@bp.get("/<election_id>/results")                # public on purpose (see the note at the top)
def results_get(election_id):
    try:
        return jsonify(published_result(election_id))
    except ResultError as e:
        return jsonify({"error": e.code, "message": e.message}), e.status
