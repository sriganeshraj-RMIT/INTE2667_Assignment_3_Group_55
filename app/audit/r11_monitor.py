"""R11 - Real-time security monitoring.

Custom rules read the tamper-proof activity log (R17) and raise ALERTS when they see an attack pattern.
Each run reads only the entries added since the last run, so it can run every few seconds:

    flask audit monitor              # keeps watching (every 5 seconds) - this is the real-time part
    flask audit monitor --once       # one pass, e.g. from a scheduler
    GET  /audit/alerts               # auditor/admin: runs a pass, then lists alerts
    POST /audit/alerts/<id>/acknowledge

Two kinds of rule:
  * IMMEDIATE: one entry is enough (e.g. the ballot box or the ballot definition was tampered with).
  * WINDOW: the same kind of failure by the same actor N times within WINDOW minutes (e.g. password guessing).
    The alert fires once, when the count reaches N, not again for every further failure.
Every run also re-checks the activity log's own hash chain (verify_log); a broken chain is a CRITICAL alert.

Alerts are kept in security_alerts (one per rule per log entry, so running twice never doubles them),
written to the activity log as SECURITY_ALERT_RAISED, and printed as a warning for the operators.
Alerts never contain passwords, codes, ballots or anything a user typed.
"""
import json
import logging
import time
from datetime import timedelta

import click
from flask import jsonify, request
from sqlalchemy.exc import IntegrityError

from . import bp
from .models import AuditEntry
from .r11_models import MonitorState, SecurityAlert
from app.common.audit import audit, verify_log
from app.common.auth import current_user, login_required, mfa_required, role_required
from app.extensions import db

READ_ROLES = ("auditor", "admin")
WINDOW = timedelta(minutes=10)
log = logging.getLogger("evp.security")

# event -> (rule, severity)
IMMEDIATE_RULES = {
    "ELECTION_DEFINITION_TAMPERED": ("BALLOT_DEFINITION_CHANGED", "CRITICAL"),
    "BALLOT_CHAIN_TAMPERED": ("BALLOT_BOX_TAMPERED", "CRITICAL"),
    "ELECTION_COUNT_MISMATCH": ("COUNTS_DISAGREE", "CRITICAL"),
    "ELECTION_COUNT_BAD_SHARES": ("BAD_KEY_SHARES", "HIGH"),
    "AUTH_MFA_LOCKED": ("MFA_LOCKED_OUT", "HIGH"),
    "BALLOT_RECEIPT_FORGED": ("FORGED_RECEIPT", "MEDIUM"),
    "BALLOT_KEY_CEREMONY_REFUSED": ("KEY_CEREMONY_ATTEMPT", "MEDIUM"),
}
SELF_APPROVAL = ("SELF_APPROVAL_ATTEMPT", "HIGH")          # any event ending in _SELF_APPROVAL_BLOCKED

NOT_A_PERSON = ("anonymous", "system")

# (rule, severity, threshold, which entries count, count per actor?)
WINDOW_RULES = [
    ("PASSWORD_GUESSING", "HIGH", 5,
     lambda e: e.event == "AUTH_LOGIN_FAILED" and e.actor_id != "anonymous", True),
    ("ACCOUNT_SCANNING", "HIGH", 10,
     lambda e: e.event == "AUTH_LOGIN_FAILED" and e.actor_id == "anonymous", True),
    ("MFA_GUESSING", "HIGH", 3,
     lambda e: e.event == "AUTH_MFA_FAILED" and e.actor_id not in NOT_A_PERSON, True),
    ("INSIDER_PROBING", "HIGH", 3,
     lambda e: e.event.endswith("_REFUSED") and e.actor_id not in NOT_A_PERSON, True),
]


class AlertError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _now():
    from app.auth.r14_models import now                    # the shared UTC clock (tests can move it)
    return now().replace(microsecond=0)


def _count_in_window(entry, matches, per_actor):
    """How many matching entries, up to and including this one, happened in the WINDOW before it."""
    query = AuditEntry.query.filter(AuditEntry.id <= entry.id, AuditEntry.created_at >= entry.created_at - WINDOW)
    if per_actor:
        query = query.filter(AuditEntry.actor_id == entry.actor_id)
    return sum(1 for e in query.all() if matches(e))


def _check_entry(entry):
    """The alerts this one log entry sets off, as (rule, severity, details)."""
    found = []
    if entry.event in IMMEDIATE_RULES:
        rule, severity = IMMEDIATE_RULES[entry.event]
        found.append((rule, severity, {"event": entry.event}))
    if entry.event.endswith("_SELF_APPROVAL_BLOCKED"):
        found.append((*SELF_APPROVAL, {"event": entry.event}))
    for rule, severity, threshold, matches, per_actor in WINDOW_RULES:
        if matches(entry) and _count_in_window(entry, matches, per_actor) == threshold:
            found.append((rule, severity, {"event": entry.event, "count": threshold,
                                           "window_minutes": int(WINDOW.total_seconds() // 60)}))
    return found


def _new_alert(rule, severity, actor_id, details, trigger_entry_id):
    exists = SecurityAlert.query.filter_by(rule=rule, trigger_entry_id=trigger_entry_id).first()
    if exists:
        return None
    alert = SecurityAlert(rule=rule, severity=severity, actor_id=actor_id or "anonymous",
                          details=json.dumps(details, sort_keys=True), trigger_entry_id=trigger_entry_id,
                          created_at=_now(), status="OPEN")
    db.session.add(alert)
    return alert


def run_rules():
    """One monitoring pass over the entries added since the last pass. Returns the new alerts."""
    state = db.session.get(MonitorState, 1)
    if state is None:
        state = MonitorState(id=1, last_entry_id=0)
        db.session.add(state)
    new_entries = AuditEntry.query.filter(AuditEntry.id > state.last_entry_id).order_by(AuditEntry.id).all()

    raised = []
    for entry in new_entries:
        for rule, severity, details in _check_entry(entry):
            alert = _new_alert(rule, severity, entry.actor_id, details, entry.id)
            if alert:
                raised.append(alert)
    if new_entries:
        state.last_entry_id = new_entries[-1].id

    integrity = verify_log()                                 # was the activity log itself changed?
    if not integrity["valid"]:
        alert = _new_alert("AUDIT_LOG_TAMPERED", "CRITICAL", "system",
                           {"problem": integrity["problem"]}, integrity["first_bad_entry"])
        if alert:
            raised.append(alert)
    try:
        db.session.commit()
    except IntegrityError:                                   # another monitor raised the same alerts first
        db.session.rollback()
        return []

    for alert in raised:                                      # after our commit: audit() commits its own row
        log.warning("SECURITY ALERT %s [%s] actor=%s", alert.rule, alert.severity, alert.actor_id)
        audit("SECURITY_ALERT_RAISED", actor_id="system",
              details={"alert_id": alert.id, "rule": alert.rule, "severity": alert.severity})
    return raised


def acknowledge(user, alert_id):
    alert = db.session.get(SecurityAlert, alert_id)
    if alert is None:
        raise AlertError("NOT_FOUND", "No such alert.", 404)
    if alert.status != "OPEN":
        raise AlertError("ALREADY_ACKNOWLEDGED", "This alert was already acknowledged.", 409)
    alert.status, alert.acknowledged_by, alert.acknowledged_at = "ACKNOWLEDGED", user["id"], _now()
    db.session.commit()
    audit("SECURITY_ALERT_ACKNOWLEDGED", actor_id=user["id"], details={"alert_id": alert.id, "rule": alert.rule})
    return alert


def as_dict(alert):
    return {"id": alert.id, "rule": alert.rule, "severity": alert.severity, "actor_id": alert.actor_id,
            "details": json.loads(alert.details), "trigger_entry_id": alert.trigger_entry_id,
            "created_at": alert.created_at.isoformat(), "status": alert.status,
            "acknowledged_by": alert.acknowledged_by,
            "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None}


# ------------------------------------------------------------------------------ web routes
@bp.get("/alerts")                               # final URL: /audit/alerts
@login_required
@role_required(*READ_ROLES)
@mfa_required
def alerts_list():
    run_rules()                                  # always show an up-to-date list
    status = request.args.get("status", "OPEN")
    if status not in ("OPEN", "ACKNOWLEDGED", "ALL"):
        return jsonify({"error": "BAD_STATUS", "message": "status must be OPEN, ACKNOWLEDGED or ALL."}), 400
    query = SecurityAlert.query
    if status != "ALL":
        query = query.filter_by(status=status)
    return jsonify([as_dict(a) for a in query.order_by(SecurityAlert.id.desc()).limit(200).all()])


@bp.post("/alerts/<int:alert_id>/acknowledge")
@login_required
@role_required(*READ_ROLES)
@mfa_required
def alerts_acknowledge(alert_id):
    user = current_user()
    if user is None:
        return jsonify({"error": "NOT_SIGNED_IN", "message": "Please sign in."}), 401
    try:
        alert = acknowledge(user, alert_id)
    except AlertError as e:
        return jsonify({"error": e.code, "message": e.message}), e.status
    return jsonify(as_dict(alert))


# ------------------------------------------------------------------------------ command line
@bp.cli.command("monitor", help="R11: watch the activity log and raise security alerts.")
@click.option("--once", is_flag=True, help="Run one pass and stop.")
@click.option("--interval", default=5, show_default=True, help="Seconds between passes.")
def monitor_command(once, interval):
    while True:
        for alert in run_rules():
            click.echo(f"ALERT {alert.severity} {alert.rule} actor={alert.actor_id} (log entry {alert.trigger_entry_id})")
        if once:
            click.echo("Monitoring pass complete.")
            return
        time.sleep(max(1, interval))
