"""R14 - Just-in-time privileged access: asking, approving, the two-person rule and the 4-hour limit."""
from datetime import timedelta

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


@pytest.mark.parametrize("who", ["voter", "delegate1", "auditor", "admin"])
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


def test_http_errors_use_the_team_error_format(app, monkeypatch):
    client = app.test_client()
    login_as(monkeypatch, "voter", MODULE)
    resp = client.post("/auth/elevation/request", json={"ticket_no": "INC-7", "reason": "x", "scope": "counting"})
    assert resp.status_code == 403
    assert set(resp.get_json()) == {"error", "message"} and resp.get_json()["error"] == "FORBIDDEN"
