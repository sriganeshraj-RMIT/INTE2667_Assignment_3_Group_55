"""R11 - Real-time security monitoring: rules over the activity log raise alerts."""
import json
import time
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

from app import create_app
from app.audit import r11_monitor as monitor
from app.audit.r11_models import SecurityAlert
from app.auth.models import Account
from app.common.audit import audit
from app.extensions import db

START = datetime(2026, 11, 1, 9, 0, 0)


@pytest.fixture
def clock(monkeypatch):
    """A clock the test can move. audit() and the monitor both read app.auth.r14_models.now()."""
    current = {"t": START}
    monkeypatch.setattr("app.auth.r14_models.now", lambda: current["t"])
    return current


@pytest.fixture
def app(clock):
    app = create_app()
    app.config.update(TESTING=True)
    with app.app_context():
        db.create_all()
        for id_, role in (("u-auditor", "auditor"), ("u-admin", "admin"), ("u-voter", "voter")):
            db.session.add(Account(id=id_, email=f"{id_}@evp.test", password_hash="x", role=role, status="ACTIVE"))
        db.session.commit()
        yield app
        db.session.remove()


def happen(times, event, actor, details=None, minutes_apart=1, clock=None):
    for _ in range(times):
        audit(event, actor_id=actor, details=details or {})
        if clock:
            clock["t"] += timedelta(minutes=minutes_apart)


def rules_raised():
    return sorted(a.rule for a in monitor.run_rules())


def signed_in_as(client, account_id):
    with client.session_transaction() as s:
        now = int(time.time())
        s.update(user_id=account_id, last_seen=now, mfa_user=account_id, mfa_at=now)


# ---------------------------------------------------------------------- password guessing
def test_five_wrong_passwords_in_ten_minutes_raise_one_alert(app, clock):
    happen(5, "AUTH_LOGIN_FAILED", "u-voter", {"reason": "wrong_password"}, clock=clock)
    alerts = monitor.run_rules()
    assert [(a.rule, a.severity, a.actor_id) for a in alerts] == [("PASSWORD_GUESSING", "HIGH", "u-voter")]


def test_four_wrong_passwords_raise_nothing(app, clock):
    happen(4, "AUTH_LOGIN_FAILED", "u-voter", clock=clock)
    assert rules_raised() == []


def test_more_failures_do_not_raise_the_same_alert_again(app, clock):
    happen(9, "AUTH_LOGIN_FAILED", "u-voter", clock=clock)
    assert rules_raised() == ["PASSWORD_GUESSING"]


def test_failures_spread_over_more_than_ten_minutes_raise_nothing(app, clock):
    happen(5, "AUTH_LOGIN_FAILED", "u-voter", minutes_apart=4, clock=clock)
    assert rules_raised() == []


def test_failures_on_different_accounts_are_counted_separately(app, clock):
    for actor in ("u-a", "u-b", "u-c", "u-d", "u-e"):
        happen(1, "AUTH_LOGIN_FAILED", actor, clock=clock)
    assert rules_raised() == []


def test_many_unknown_emails_look_like_account_scanning(app, clock):
    happen(10, "AUTH_LOGIN_FAILED", "anonymous", {"reason": "unknown_email"}, minutes_apart=0.5, clock=clock)
    assert rules_raised() == ["ACCOUNT_SCANNING"]


# ------------------------------------------------------------------------- second step (MFA)
def test_three_wrong_mfa_codes_raise_an_alert(app, clock):
    happen(3, "AUTH_MFA_FAILED", "u-voter", clock=clock)
    assert rules_raised() == ["MFA_GUESSING"]


def test_an_mfa_lockout_raises_an_alert_straight_away(app, clock):
    happen(1, "AUTH_MFA_LOCKED", "u-voter", clock=clock)
    assert rules_raised() == ["MFA_LOCKED_OUT"]


# --------------------------------------------------------------------------- insider misuse
def test_a_staff_member_refused_three_times_is_flagged(app, clock):
    happen(1, "ELECTION_COUNT_REFUSED", "u-admin", clock=clock)
    happen(1, "AUTH_ELEVATION_REFUSED", "u-admin", clock=clock)
    happen(1, "ELECTION_RESULTS_REFUSED", "u-admin", clock=clock)
    assert rules_raised() == ["INSIDER_PROBING"]


def test_trying_to_approve_your_own_request_is_flagged(app, clock):
    happen(1, "ELECTION_EXCLUSION_SELF_APPROVAL_BLOCKED", "u-admin", clock=clock)
    alert = monitor.run_rules()[0]
    assert alert.rule == "SELF_APPROVAL_ATTEMPT" and alert.actor_id == "u-admin"


# ------------------------------------------------------------------------ tampering = critical
@pytest.mark.parametrize("event,rule", [
    ("ELECTION_DEFINITION_TAMPERED", "BALLOT_DEFINITION_CHANGED"),
    ("BALLOT_CHAIN_TAMPERED", "BALLOT_BOX_TAMPERED"),
    ("ELECTION_COUNT_MISMATCH", "COUNTS_DISAGREE"),
])
def test_tampering_events_raise_critical_alerts(app, clock, event, rule):
    happen(1, event, "system", {"election_id": "e1"}, clock=clock)
    alert = monitor.run_rules()[0]
    assert alert.rule == rule and alert.severity == "CRITICAL"


@pytest.mark.parametrize("event,rule", [
    ("BALLOT_RECEIPT_FORGED", "FORGED_RECEIPT"),
    ("ELECTION_COUNT_BAD_SHARES", "BAD_KEY_SHARES"),
    ("BALLOT_KEY_CEREMONY_REFUSED", "KEY_CEREMONY_ATTEMPT"),
])
def test_suspicious_ballot_events_raise_alerts(app, clock, event, rule):
    happen(1, event, "anonymous", clock=clock)
    assert rules_raised() == [rule]


def test_changing_the_activity_log_itself_is_a_critical_alert(app, clock):
    happen(3, "AUTH_LOGOUT", "u-voter", clock=clock)
    db.session.execute(text("UPDATE audit_log SET actor_id = 'someone-else' WHERE id = 2"))
    db.session.commit()
    alert = monitor.run_rules()[0]
    assert alert.rule == "AUDIT_LOG_TAMPERED" and alert.severity == "CRITICAL" and alert.trigger_entry_id == 2


# --------------------------------------------------------------- normal activity, repeated runs
def test_normal_activity_raises_nothing(app, clock):
    for event in ("AUTH_LOGIN_PASSWORD_OK", "AUTH_MFA_PASSED", "ELECTION_DEFINITION_LOCKED",
                  "BALLOT_BATCH_STORED", "ELECTION_RESULTS_PUBLISHED", "AUTH_LOGOUT"):
        happen(2, event, "u-admin", clock=clock)
    assert rules_raised() == []


def test_running_twice_never_doubles_an_alert(app, clock):
    happen(1, "BALLOT_CHAIN_TAMPERED", "system", clock=clock)
    assert len(monitor.run_rules()) == 1
    assert monitor.run_rules() == []
    assert SecurityAlert.query.count() == 1


def test_each_pass_only_reads_new_entries(app, clock):
    happen(3, "AUTH_LOGIN_FAILED", "u-voter", clock=clock)
    assert rules_raised() == []
    happen(2, "AUTH_LOGIN_FAILED", "u-voter", clock=clock)          # the window still includes the first three
    assert rules_raised() == ["PASSWORD_GUESSING"]


def test_an_alert_is_written_to_the_activity_log_without_secrets(app, clock):
    happen(5, "AUTH_LOGIN_FAILED", "u-voter", {"reason": "wrong_password"}, clock=clock)
    alert = monitor.run_rules()[0]
    from app.audit.models import AuditEntry
    last = AuditEntry.query.order_by(AuditEntry.id.desc()).first()
    assert last.event == "SECURITY_ALERT_RAISED" and last.actor_id == "system"
    assert json.loads(last.details) == {"alert_id": alert.id, "rule": "PASSWORD_GUESSING", "severity": "HIGH"}
    assert json.loads(alert.details) == {"event": "AUTH_LOGIN_FAILED", "count": 5, "window_minutes": 10}


# ---------------------------------------------------------------------------------- routes
def test_an_auditor_sees_alerts_and_can_acknowledge_them(app, clock):
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    happen(1, "BALLOT_CHAIN_TAMPERED", "system", clock=clock)
    client = app.test_client()
    signed_in_as(client, "u-auditor")
    alerts = client.get("/audit/alerts").get_json()                     # the list runs a pass first
    assert [a["rule"] for a in alerts] == ["BALLOT_BOX_TAMPERED"]
    body = client.post(f"/audit/alerts/{alerts[0]['id']}/acknowledge").get_json()
    assert body["status"] == "ACKNOWLEDGED" and body["acknowledged_by"] == "u-auditor"
    assert client.get("/audit/alerts").get_json() == []                 # no longer open
    assert len(client.get("/audit/alerts?status=ALL").get_json()) == 1


def test_an_alert_cannot_be_acknowledged_twice(app, clock):
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    happen(1, "BALLOT_CHAIN_TAMPERED", "system", clock=clock)
    client = app.test_client()
    signed_in_as(client, "u-admin")
    alert_id = client.get("/audit/alerts").get_json()[0]["id"]
    client.post(f"/audit/alerts/{alert_id}/acknowledge")
    resp = client.post(f"/audit/alerts/{alert_id}/acknowledge")
    assert resp.status_code == 409 and resp.get_json()["error"] == "ALREADY_ACKNOWLEDGED"
    assert client.post("/audit/alerts/999/acknowledge").status_code == 404


def test_voters_and_signed_out_users_cannot_see_alerts(app):
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    client = app.test_client()
    assert client.get("/audit/alerts").status_code == 401
    signed_in_as(client, "u-voter")
    assert client.get("/audit/alerts").status_code == 403
    assert client.post("/audit/alerts/1/acknowledge").status_code == 403


def test_a_bad_status_filter_is_refused(app):
    resp = app.test_client().get("/audit/alerts?status=<script>")
    assert resp.status_code == 400 and resp.get_json()["error"] == "BAD_STATUS"


def test_monitor_command_prints_alerts(app, clock):
    happen(1, "ELECTION_COUNT_MISMATCH", "system", clock=clock)
    out = app.test_cli_runner().invoke(args=["audit", "monitor", "--once"])
    assert "ALERT CRITICAL COUNTS_DISAGREE" in out.output and "Monitoring pass complete." in out.output
