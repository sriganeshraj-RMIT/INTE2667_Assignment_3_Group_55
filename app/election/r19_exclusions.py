"""R19 - Two-person rule for candidate exclusions.

One delegate PROPOSES excluding a candidate (for example after a court order). A DIFFERENT delegate must
APPROVE it, after a fresh second sign-in step (@mfa_required). Until both steps are done nothing changes in the
count. Both steps are written to the audit log, so one account can never change a result alone.
"""
from flask import jsonify, request
from sqlalchemy import text, update

from . import bp
from app.auth.r14_models import now
from app.common.audit import audit
from app.common.auth import current_user, login_required, mfa_required, role_required
from app.common.validate import validate
from app.extensions import db
from .r19_models import Exclusion

DELEGATE_ROLES = ("delegate",)

PROPOSE_SCHEMA = {
    "election_id":  {"type": str, "max_length": 36, "required": True},
    "candidate_id": {"type": str, "max_length": 36, "required": True},
    "reason":       {"type": str, "max_length": 200, "required": True},
}


class ExclusionError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


def _require_delegate(user, action, **details):
    """Only delegates may touch exclusions. A wrong-role attempt is logged (R11 can watch for these)."""
    if not user or user.get("role") not in DELEGATE_ROLES:
        audit("ELECTION_EXCLUSION_REFUSED", actor_id=(user or {}).get("id", "anonymous"),
              details={"action": action, "role": (user or {}).get("role"), **details})
        raise ExclusionError("FORBIDDEN", "Only a delegate can do this.", 403)


# ------------------------------------------------------------------ logic
def propose_exclusion(user, election_id, candidate_id, reason):
    _require_delegate(user, "propose", election_id=election_id, candidate_id=candidate_id)
    found = db.session.execute(                      # bound parameters only, never string-built SQL
        text("SELECT 1 FROM candidates WHERE id = :cid AND election_id = :eid"),
        {"cid": candidate_id, "eid": election_id}).first()
    if found is None:
        raise ExclusionError("NOT_FOUND", "That candidate is not in this election.", 404)
    already = db.session.query(Exclusion).filter_by(
        election_id=election_id, candidate_id=candidate_id, status="PENDING").first()
    if already is not None:
        raise ExclusionError("DUPLICATE", "An exclusion for this candidate is already waiting.", 409)
    exclusion = Exclusion(election_id=election_id, candidate_id=candidate_id, reason=reason.strip(),
                          proposed_by=user["id"])
    db.session.add(exclusion)
    db.session.commit()
    audit("ELECTION_EXCLUSION_PROPOSED", actor_id=user["id"],
          details={"exclusion_id": exclusion.id, "election_id": election_id, "candidate_id": candidate_id})
    return exclusion


def approve_exclusion(user, exclusion_id):
    _require_delegate(user, "approve", exclusion_id=exclusion_id)
    exclusion = db.session.get(Exclusion, exclusion_id)
    if exclusion is None:
        raise ExclusionError("NOT_FOUND", "No exclusion with that ID.", 404)
    if exclusion.status != "PENDING":
        raise ExclusionError("ALREADY_DECIDED", "This exclusion has already been decided.", 409)
    if exclusion.proposed_by == user["id"]:                    # the two-person rule
        audit("ELECTION_EXCLUSION_SELF_APPROVAL_BLOCKED", actor_id=user["id"],
              details={"exclusion_id": exclusion.id})
        raise ExclusionError("SELF_APPROVAL", "A second delegate must approve this exclusion.", 403)
    # ONE update that only succeeds while the exclusion is still pending and not the approver's own.
    result = db.session.execute(
        update(Exclusion)
        .where(Exclusion.id == exclusion.id, Exclusion.status == "PENDING", Exclusion.proposed_by != user["id"])
        .values(status="APPROVED", approved_by=user["id"], decided_at=now())
        .execution_options(synchronize_session=False))
    db.session.commit()
    if result.rowcount != 1:
        raise ExclusionError("ALREADY_DECIDED", "This exclusion has already been decided.", 409)
    audit("ELECTION_EXCLUSION_APPROVED", actor_id=user["id"],
          details={"exclusion_id": exclusion.id, "candidate_id": exclusion.candidate_id})
    return db.session.get(Exclusion, exclusion.id)


def reject_exclusion(user, exclusion_id):
    _require_delegate(user, "reject", exclusion_id=exclusion_id)
    exclusion = db.session.get(Exclusion, exclusion_id)
    if exclusion is None:
        raise ExclusionError("NOT_FOUND", "No exclusion with that ID.", 404)
    if exclusion.status != "PENDING":
        raise ExclusionError("ALREADY_DECIDED", "This exclusion has already been decided.", 409)
    result = db.session.execute(
        update(Exclusion).where(Exclusion.id == exclusion.id, Exclusion.status == "PENDING")
        .values(status="REJECTED", decided_at=now()).execution_options(synchronize_session=False))
    db.session.commit()
    if result.rowcount != 1:
        raise ExclusionError("ALREADY_DECIDED", "This exclusion has already been decided.", 409)
    audit("ELECTION_EXCLUSION_REJECTED", actor_id=user["id"], details={"exclusion_id": exclusion.id})
    return db.session.get(Exclusion, exclusion.id)


def approved_candidate_ids(election_id):
    """Used by the count (R7): candidates whose exclusion was approved by a second delegate."""
    rows = db.session.query(Exclusion.candidate_id).filter_by(election_id=election_id, status="APPROVED").all()
    return [r[0] for r in rows]


# ----------------------------------------------------------------- routes
@bp.post("/exclusions")                          # final URL: /election/exclusions
@login_required
@role_required("delegate")
def exclusion_propose():
    data = validate(PROPOSE_SCHEMA, request.get_json() or {})
    try:
        ex = propose_exclusion(current_user(), data["election_id"], data["candidate_id"], data["reason"])
    except ExclusionError as e:
        return error_response(e)
    return jsonify({"exclusion_id": ex.id, "status": ex.status}), 201


@bp.post("/exclusions/<exclusion_id>/approve")
@login_required
@role_required("delegate")
@mfa_required                                    # the approver must have passed a fresh second sign-in step
def exclusion_approve(exclusion_id):
    try:
        ex = approve_exclusion(current_user(), exclusion_id)
    except ExclusionError as e:
        return error_response(e)
    return jsonify({"status": ex.status})


@bp.post("/exclusions/<exclusion_id>/reject")
@login_required
@role_required("delegate")
def exclusion_reject(exclusion_id):
    try:
        ex = reject_exclusion(current_user(), exclusion_id)
    except ExclusionError as e:
        return error_response(e)
    return jsonify({"status": ex.status})
