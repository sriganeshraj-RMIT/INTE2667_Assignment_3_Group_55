"""R14 - Just-in-time privileged access.

How it works (one sentence each):
  1. A counting officer asks for access: ticket number, reason and scope ("counting" or "results").
  2. A DIFFERENT person (admin or custodian) approves it. Nobody can approve their own request.
  3. The approval lasts ELEVATION_HOURS (4). After that the access is gone, with nobody having to remove it.
  4. Other code protects a sensitive route with @elevation_required("counting").
"""
from datetime import timedelta
from functools import wraps

from flask import jsonify, request

from . import bp
from app.common.audit import audit
from app.common.auth import current_user, login_required, role_required
from app.common.validate import validate
from app.extensions import db
from .r14_models import AccessGrant, now

ELEVATION_HOURS = 4
SCOPES = ("counting", "results")
REQUEST_ROLES = ("counting_officer",)
APPROVER_ROLES = ("admin", "custodian")

REQUEST_SCHEMA = {
    "ticket_no": {"type": str, "max_length": 20, "required": True},
    "reason":    {"type": str, "max_length": 200, "required": True},
    "scope":     {"type": str, "max_length": 20, "required": True},
}


class AccessError(Exception):
    """A refusal that is turned into the team's error JSON: {"error": CODE, "message": text}."""

    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


# ------------------------------------------------------------------ logic
def request_access(user, ticket_no, reason, scope):
    if not user or user.get("role") not in REQUEST_ROLES:
        raise AccessError("FORBIDDEN", "Only a counting officer can ask for this access.", 403)
    if scope not in SCOPES:
        raise AccessError("INVALID_SCOPE", "Scope must be 'counting' or 'results'.", 400)
    if not ticket_no.strip() or not reason.strip():
        raise AccessError("VALIDATION_FAILED", "A ticket number and a reason are required.", 400)
    grant = AccessGrant(requester_id=user["id"], ticket_no=ticket_no.strip(), reason=reason.strip(), scope=scope)
    db.session.add(grant)
    db.session.commit()
    audit("AUTH_ELEVATION_REQUESTED", actor_id=user["id"],
          details={"grant_id": grant.id, "scope": scope, "ticket_no": grant.ticket_no})
    return grant


def approve_access(user, grant_id):
    if not user or user.get("role") not in APPROVER_ROLES:
        raise AccessError("FORBIDDEN", "Only an admin or custodian can approve access.", 403)
    grant = db.session.get(AccessGrant, grant_id)
    if grant is None:
        raise AccessError("NOT_FOUND", "No access request with that ID.", 404)
    if grant.status != "PENDING":
        raise AccessError("ALREADY_DECIDED", "This request has already been decided.", 409)
    if grant.requester_id == user["id"]:                      # the two-person rule
        audit("AUTH_ELEVATION_SELF_APPROVAL_BLOCKED", actor_id=user["id"], details={"grant_id": grant.id})
        raise AccessError("SELF_APPROVAL", "A second person must approve your request.", 403)
    grant.status = "APPROVED"
    grant.approver_id = user["id"]
    grant.approved_at = now()
    grant.expires_at = grant.approved_at + timedelta(hours=ELEVATION_HOURS)
    db.session.commit()
    audit("AUTH_ELEVATION_APPROVED", actor_id=user["id"],
          details={"grant_id": grant.id, "scope": grant.scope, "expires_at": grant.expires_at.isoformat()})
    return grant


def has_active_grant(user_id, scope):
    """True only while an APPROVED, unexpired grant for this person and scope exists."""
    return db.session.query(AccessGrant).filter(
        AccessGrant.requester_id == user_id,
        AccessGrant.scope == scope,
        AccessGrant.status == "APPROVED",
        AccessGrant.expires_at > now(),
    ).first() is not None


def elevation_required(scope):
    """Use under @login_required / @role_required:  refuses the request unless the caller has live access."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = current_user()
            if not user or not has_active_grant(user["id"], scope):
                audit("AUTH_ELEVATION_DENIED", actor_id=(user or {}).get("id", "anonymous"), details={"scope": scope})
                return jsonify({"error": "ELEVATION_REQUIRED",
                                "message": "Approved, time-limited access is needed for this action."}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ----------------------------------------------------------------- routes
@bp.post("/elevation/request")                  # final URL: /auth/elevation/request
@login_required
@role_required("counting_officer")
def elevation_request():
    data = validate(REQUEST_SCHEMA, request.get_json() or {})
    try:
        grant = request_access(current_user(), data["ticket_no"], data["reason"], data["scope"])
    except AccessError as e:
        return error_response(e)
    return jsonify({"grant_id": grant.id, "status": grant.status}), 201


@bp.post("/elevation/<grant_id>/approve")       # final URL: /auth/elevation/<id>/approve
@login_required
@role_required("admin", "custodian")
def elevation_approve(grant_id):
    try:
        grant = approve_access(current_user(), grant_id)
    except AccessError as e:
        return error_response(e)
    return jsonify({"status": grant.status, "expires_at": grant.expires_at.isoformat()})
