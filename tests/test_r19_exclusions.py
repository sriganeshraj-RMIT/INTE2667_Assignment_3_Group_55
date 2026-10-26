"""R19 - Two-person rule for candidate exclusions."""
import pytest

from app import create_app
from app.election import r19_exclusions as r19
from app.election.r19_models import Exclusion
from app.extensions import db
from tests.setd_helpers import USERS, add_election, create_base_tables, login_as

MODULE = "app.election.r19_exclusions"


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        create_base_tables()
        add_election("e1", "CLOSED", ("c1", "c2", "c3"))
        yield app
        db.session.remove()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


def propose(who="delegate1", candidate="c1"):
    return r19.propose_exclusion(USERS[who], "e1", candidate, "Court of Disputed Returns order")


# ---------------------------------------------------------------- proposing
def test_a_delegate_can_propose_and_nothing_is_excluded_yet(app, audit_log):
    ex = propose()
    assert ex.status == "PENDING"
    assert r19.approved_candidate_ids("e1") == []                  # a proposal changes nothing
    assert audit_log[0][0] == "ELECTION_EXCLUSION_PROPOSED"


@pytest.mark.parametrize("who", ["voter", "counter", "admin", "auditor"])
def test_only_delegates_can_propose(app, who):
    with pytest.raises(r19.ExclusionError) as e:
        propose(who)
    assert e.value.status == 403


def test_the_candidate_must_belong_to_the_election(app):
    with pytest.raises(r19.ExclusionError) as e:
        propose(candidate="not-a-candidate")
    assert e.value.status == 404


def test_the_same_candidate_cannot_be_proposed_twice_at_once(app):
    propose()
    with pytest.raises(r19.ExclusionError) as e:
        propose("delegate2", "c1")
    assert e.value.code == "DUPLICATE"


# ---------------------------------------------------------------- approving
def test_a_second_delegate_approves_and_both_steps_are_logged(app, audit_log):
    ex = propose("delegate1")
    r19.approve_exclusion(USERS["delegate2"], ex.id)
    assert r19.approved_candidate_ids("e1") == ["c1"]
    assert [c[0] for c in audit_log] == ["ELECTION_EXCLUSION_PROPOSED", "ELECTION_EXCLUSION_APPROVED"]
    assert audit_log[0][1] == USERS["delegate1"]["id"] and audit_log[1][1] == USERS["delegate2"]["id"]


def test_one_delegate_alone_can_never_exclude_a_candidate(app, audit_log):
    ex = propose("delegate1")
    with pytest.raises(r19.ExclusionError) as e:
        r19.approve_exclusion(USERS["delegate1"], ex.id)
    assert e.value.code == "SELF_APPROVAL" and e.value.status == 403
    assert db.session.get(Exclusion, ex.id).status == "PENDING"
    assert r19.approved_candidate_ids("e1") == []
    assert "ELECTION_EXCLUSION_SELF_APPROVAL_BLOCKED" in [c[0] for c in audit_log]


@pytest.mark.parametrize("who", ["voter", "counter", "admin", "auditor"])
def test_only_delegates_can_approve(app, who):
    ex = propose()
    with pytest.raises(r19.ExclusionError) as e:
        r19.approve_exclusion(USERS[who], ex.id)
    assert e.value.status == 403


def test_a_decision_cannot_be_made_twice(app):
    ex = propose()
    r19.approve_exclusion(USERS["delegate2"], ex.id)
    with pytest.raises(r19.ExclusionError) as e:
        r19.approve_exclusion(USERS["delegate2"], ex.id)
    assert e.value.code == "ALREADY_DECIDED"


def test_a_rejected_exclusion_changes_nothing(app, audit_log):
    ex = propose()
    r19.reject_exclusion(USERS["delegate2"], ex.id)
    assert r19.approved_candidate_ids("e1") == []
    assert audit_log[-1][0] == "ELECTION_EXCLUSION_REJECTED"


def test_exclusions_are_per_election(app):
    add_election("e2", "CLOSED", ("d1", "d2"))
    ex = propose()
    r19.approve_exclusion(USERS["delegate2"], ex.id)
    assert r19.approved_candidate_ids("e2") == []


# --------------------------------------------------------------------- HTTP
def test_http_flow_and_error_format(app, monkeypatch):
    client = app.test_client()
    body = {"election_id": "e1", "candidate_id": "c2", "reason": "Court order"}
    login_as(monkeypatch, "delegate1", MODULE)
    resp = client.post("/election/exclusions", json=body)
    assert resp.status_code == 201
    exclusion_id = resp.get_json()["exclusion_id"]

    resp = client.post(f"/election/exclusions/{exclusion_id}/approve")        # the proposer tries to approve
    assert resp.status_code == 403 and resp.get_json()["error"] == "SELF_APPROVAL"
    assert set(resp.get_json()) == {"error", "message"}

    login_as(monkeypatch, "delegate2", MODULE)
    resp = client.post(f"/election/exclusions/{exclusion_id}/approve")
    assert resp.status_code == 200 and resp.get_json() == {"status": "APPROVED"}


def test_signed_out_requests_are_refused(app, monkeypatch):
    login_as(monkeypatch, None, MODULE)
    resp = app.test_client().post("/election/exclusions", json={"election_id": "e1", "candidate_id": "c1", "reason": "x"})
    assert resp.status_code == 403


def test_sql_injection_text_is_just_text(app):
    with pytest.raises(r19.ExclusionError) as e:
        r19.propose_exclusion(USERS["delegate1"], "e1", "c1' OR '1'='1", "x")
    assert e.value.status == 404
    assert db.session.query(Exclusion).count() == 0


@pytest.mark.skip(reason="Turn on when R12 (mfa_required) is merged: approving without a fresh MFA check must be refused")
def test_approve_needs_a_fresh_second_sign_in_step(app):
    ...
