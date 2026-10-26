"""R14 - Just-in-time privileged access: asking, approving, the two-person rule and the 4-hour limit."""
from datetime import timedelta
from types import SimpleNamespace

import pytest

from app import create_app
from app.auth import r14_elevation as r14
from app.auth.r14_models import AccessGrant, now
from app.extensions import db
from tests.setd_helpers import USERS, login_as

MODULE = "app.auth.r14_elevation"


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True

    @app.get("/_protected")                       # a throw-away route that uses the decorator
    @r14.elevation_required("counting")
    def protected():
        return {"ok": True}

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


def new_request(scope="counting"):
    return r14.request_access(USERS["counter"], "INC-1042", "Run the count", scope)


# ------------------------------------------------------------ asking
def test_counting_officer_can_ask_and_it_is_logged(app, audit_log):
    grant = new_request()
    assert grant.status == "PENDING" and grant.expires_at is None
    assert audit_log[0][0] == "AUTH_ELEVATION_REQUESTED" and audit_log[0][1] == USERS["counter"]["id"]


@pytest.mark.parametrize("who", ["voter", "delegate1", "auditor", "custodian"])
def test_other_roles_cannot_ask(app, who):
    with pytest.raises(r14.AccessError) as e:
        r14.request_access(USERS[who], "INC-1", "Because", "counting")
    assert e.value.status == 403


def test_nobody_signed_in_cannot_ask(app):
    with pytest.raises(r14.AccessError) as e:
        r14.request_access(None, "INC-1", "Because", "counting")
    assert e.value.status == 403


def test_unknown_scope_is_refused(app):
    with pytest.raises(r14.AccessError) as e:
        r14.request_access(USERS["counter"], "INC-1", "Because", "everything")
    assert e.value.code == "INVALID_SCOPE"


def test_an_admin_can_ask_for_access_too(app, audit_log):
    """R14 is about administrators: an admin must also get a second person's approval."""
    grant = r14.request_access(USERS["admin"], "INC-9", "Fix the count service", "counting")
    assert grant.status == "PENDING" and grant.requester_id == USERS["admin"]["id"]
    assert audit_log[0][0] == "AUTH_ELEVATION_REQUESTED"


def test_one_admin_asks_and_a_different_admin_approves(app, audit_log):
    grant = r14.request_access(USERS["admin"], "INC-9", "Fix the count service", "counting")
    approved = r14.approve_access(USERS["admin2"], grant.id)
    assert approved.status == "APPROVED" and approved.approver_id == USERS["admin2"]["id"]
    assert r14.has_active_grant(USERS["admin"]["id"], "counting")            # the REQUESTING admin gets the access
    assert not r14.has_active_grant(USERS["admin2"]["id"], "counting")        # the approver does not


def test_an_admin_cannot_approve_their_own_request(app, audit_log):
    grant = r14.request_access(USERS["admin"], "INC-9", "Fix the count service", "counting")
    with pytest.raises(r14.AccessError) as e:
        r14.approve_access(USERS["admin"], grant.id)                         # same admin, same ID
    assert e.value.code == "SELF_APPROVAL" and e.value.status == 403
    assert db.session.get(AccessGrant, grant.id).status == "PENDING"
    assert not r14.has_active_grant(USERS["admin"]["id"], "counting")
    assert "AUTH_ELEVATION_SELF_APPROVAL_BLOCKED" in [c[0] for c in audit_log]


# --------------------------------------------------------- approving
def test_admin_approval_starts_a_four_hour_window(app, audit_log):
    grant = new_request()
    approved = r14.approve_access(USERS["admin"], grant.id)
    assert approved.status == "APPROVED" and approved.approver_id == USERS["admin"]["id"]
    assert approved.expires_at - approved.approved_at == timedelta(hours=4)
    assert [c[0] for c in audit_log] == ["AUTH_ELEVATION_REQUESTED", "AUTH_ELEVATION_APPROVED"]


def test_custodian_can_approve_too(app):
    assert r14.approve_access(USERS["custodian"], new_request().id).status == "APPROVED"


def test_nobody_approves_their_own_request(app, audit_log):
    grant = new_request()
    same_person_now_admin = dict(USERS["admin"], id=USERS["counter"]["id"])
    with pytest.raises(r14.AccessError) as e:
        r14.approve_access(same_person_now_admin, grant.id)
    assert e.value.code == "SELF_APPROVAL" and e.value.status == 403
    assert db.session.get(AccessGrant, grant.id).status == "PENDING"
    assert "AUTH_ELEVATION_SELF_APPROVAL_BLOCKED" in [c[0] for c in audit_log]


@pytest.mark.parametrize("who", ["counter2", "delegate1", "voter", "auditor"])
def test_only_admin_or_custodian_can_approve(app, who):
    grant = new_request()
    with pytest.raises(r14.AccessError) as e:
        r14.approve_access(USERS[who], grant.id)
    assert e.value.status == 403


def test_a_request_is_decided_only_once(app):
    grant = new_request()
    r14.approve_access(USERS["admin"], grant.id)
    with pytest.raises(r14.AccessError) as e:
        r14.approve_access(USERS["custodian"], grant.id)
    assert e.value.code == "ALREADY_DECIDED"


def test_unknown_request_is_not_found(app):
    with pytest.raises(r14.AccessError) as e:
        r14.approve_access(USERS["admin"], "does-not-exist")
    assert e.value.status == 404


def test_two_approvers_at_the_same_moment_only_one_wins(app, monkeypatch):
    """Both approvers read 'still pending' before either has written. Only the first UPDATE may succeed."""
    grant = new_request()
    stale = SimpleNamespace(id=grant.id, status="PENDING", requester_id=USERS["counter"]["id"], scope="counting")
    r14.approve_access(USERS["admin"], grant.id)                              # the first approver wins
    monkeypatch.setattr(r14.db.session, "get", lambda model, pk: stale)       # the second one still sees 'pending'
    with pytest.raises(r14.AccessError) as e:
        r14.approve_access(USERS["custodian"], grant.id)
    assert e.value.code == "ALREADY_DECIDED" and e.value.status == 409
    monkeypatch.undo()
    assert db.session.get(AccessGrant, grant.id).approver_id == USERS["admin"]["id"]     # not overwritten


# ------------------------------------------- refused attempts are logged (for R11)
def test_a_refused_request_is_logged(app, audit_log):
    with pytest.raises(r14.AccessError):
        r14.request_access(USERS["voter"], "INC-1", "Because", "counting")
    event, actor, details = audit_log[-1]
    assert event == "AUTH_ELEVATION_REFUSED" and actor == USERS["voter"]["id"]
    assert details["action"] == "request" and details["role"] == "voter"


def test_a_refused_approval_is_logged(app, audit_log):
    grant = new_request()
    with pytest.raises(r14.AccessError):
        r14.approve_access(USERS["counter2"], grant.id)                      # a counting officer cannot approve
    event, actor, details = audit_log[-1]
    assert event == "AUTH_ELEVATION_REFUSED" and actor == USERS["counter2"]["id"]
    assert details["action"] == "approve" and details["grant_id"] == grant.id


def test_a_refused_attempt_by_nobody_is_logged_as_anonymous(app, audit_log):
    with pytest.raises(r14.AccessError):
        r14.request_access(None, "INC-1", "Because", "counting")
    assert audit_log[-1][0] == "AUTH_ELEVATION_REFUSED" and audit_log[-1][1] == "anonymous"


# --------------------------------------------- the access switches itself off
def test_access_exists_only_when_approved(app):
    grant = new_request()
    assert not r14.has_active_grant(USERS["counter"]["id"], "counting")        # pending is not enough
    r14.approve_access(USERS["admin"], grant.id)
    assert r14.has_active_grant(USERS["counter"]["id"], "counting")


def test_access_ends_after_four_hours(app, monkeypatch):
    r14.approve_access(USERS["admin"], new_request().id)
    start = now()
    monkeypatch.setattr("app.auth.r14_elevation.now", lambda: start + timedelta(hours=3, minutes=59))
    assert r14.has_active_grant(USERS["counter"]["id"], "counting")
    monkeypatch.setattr("app.auth.r14_elevation.now", lambda: start + timedelta(hours=4, minutes=1))
    assert not r14.has_active_grant(USERS["counter"]["id"], "counting")


def test_access_is_for_one_person_and_one_scope(app):
    r14.approve_access(USERS["admin"], new_request("counting").id)
    assert not r14.has_active_grant(USERS["counter"]["id"], "results")          # other scope
    assert not r14.has_active_grant(USERS["counter2"]["id"], "counting")        # other person


# ----------------------------------------------------- the decorator + routes
def test_protected_route_is_refused_without_access(app, monkeypatch, audit_log):
    login_as(monkeypatch, "counter", MODULE)
    resp = app.test_client().get("/_protected")
    assert resp.status_code == 403 and resp.get_json()["error"] == "ELEVATION_REQUIRED"
    assert audit_log[-1][0] == "AUTH_ELEVATION_DENIED"


def test_protected_route_is_refused_when_nobody_is_signed_in(app, monkeypatch):
    login_as(monkeypatch, None, MODULE)
    assert app.test_client().get("/_protected").status_code == 403


def test_protected_route_works_with_live_access_and_stops_after_expiry(app, monkeypatch):
    login_as(monkeypatch, "counter", MODULE)
    r14.approve_access(USERS["admin"], new_request().id)
    client = app.test_client()
    assert client.get("/_protected").status_code == 200
    later = now() + timedelta(hours=5)
    monkeypatch.setattr("app.auth.r14_elevation.now", lambda: later)
    assert client.get("/_protected").status_code == 403


def test_http_flow_request_then_approve(app, monkeypatch):
    client = app.test_client()
    login_as(monkeypatch, "counter", MODULE)
    resp = client.post("/auth/elevation/request",
                       json={"ticket_no": "INC-7", "reason": "Count the votes", "scope": "counting"})
    assert resp.status_code == 201
    grant_id = resp.get_json()["grant_id"]
    login_as(monkeypatch, "admin", MODULE)
    resp = client.post(f"/auth/elevation/{grant_id}/approve")
    assert resp.status_code == 200 and "expires_at" in resp.get_json()


def test_http_flow_admin_asks_and_a_second_admin_approves(app, monkeypatch):
    client = app.test_client()
    login_as(monkeypatch, "admin", MODULE)
    resp = client.post("/auth/elevation/request",
                       json={"ticket_no": "INC-8", "reason": "Fix the count service", "scope": "counting"})
    assert resp.status_code == 201
    grant_id = resp.get_json()["grant_id"]
    assert client.post(f"/auth/elevation/{grant_id}/approve").get_json()["error"] == "SELF_APPROVAL"
    login_as(monkeypatch, "admin2", MODULE)
    assert client.post(f"/auth/elevation/{grant_id}/approve").status_code == 200


def test_http_errors_use_the_team_error_format(app, monkeypatch):
    client = app.test_client()
    login_as(monkeypatch, "voter", MODULE)
    resp = client.post("/auth/elevation/request", json={"ticket_no": "INC-7", "reason": "x", "scope": "counting"})
    assert resp.status_code == 403
    assert set(resp.get_json()) == {"error", "message"} and resp.get_json()["error"] == "FORBIDDEN"
