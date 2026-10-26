"""R10 - candidate list, party order and polling times locked and signed before polls open."""
import time
from datetime import timedelta

import pytest
from sqlalchemy import text

from app import create_app
from app.auth.models import Account
from app.common import crypto
from app.election import r10_lock as r10
from app.extensions import db

DELEGATE = {"id": "u-delegate", "role": "delegate", "division": None, "state": None}
OFFICER = {"id": "u-officer", "role": "officer", "division": None, "state": None}


def make_tables():
    db.session.execute(text("""CREATE TABLE elections (
        id TEXT PRIMARY KEY, name TEXT, division TEXT, state TEXT, opens_at DATETIME, closes_at DATETIME,
        definition_fp TEXT, definition_sig TEXT, status TEXT DEFAULT 'DRAFT')"""))
    db.session.execute(text("""CREATE TABLE candidates (
        id TEXT PRIMARY KEY, election_id TEXT, name TEXT, party TEXT, ballot_pos INTEGER)"""))


def add_election(eid="e1", opens_in=timedelta(days=1), length=timedelta(hours=10), positions=(1, 2, 3)):
    opens = (r10.now() + opens_in).replace(microsecond=0)
    db.session.execute(text("INSERT INTO elections (id, name, division, state, opens_at, closes_at, status) "
                            "VALUES (:id, 'Test', 'Melbourne', 'VIC', :o, :c, 'DRAFT')"),
                       {"id": eid, "o": str(opens), "c": str(opens + length)})
    for i, pos in enumerate(positions, 1):
        db.session.execute(text("INSERT INTO candidates VALUES (:id, :eid, :name, :party, :pos)"),
                           {"id": f"{eid}-c{i}", "eid": eid, "name": f"Candidate {i}", "party": f"Party {i}", "pos": pos})
    db.session.commit()


def status(eid="e1"):
    return db.session.execute(text("SELECT status FROM elections WHERE id = :e"), {"e": eid}).scalar()


@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True)
    with app.app_context():
        db.create_all()
        make_tables()
        add_election()
        yield app
        db.session.remove()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr("app.election.r10_lock.audit", lambda event, actor_id, details: calls.append(event))
    return calls


# ------------------------------------------------------------------ locking
def test_delegate_locks_and_the_definition_is_signed(app, audit_log):
    fp = r10.lock_election(DELEGATE, "e1")
    assert status() == "APPROVED"
    check = r10.check_definition("e1")
    assert check["valid"] and check["definition_fp"] == fp
    assert [c["ballot_pos"] for c in check["definition"]["candidates"]] == [1, 2, 3]
    assert crypto.verify(fp.encode(), check["signature"])
    assert audit_log == ["ELECTION_DEFINITION_LOCKED"]


def test_only_a_delegate_can_lock(app, audit_log):
    with pytest.raises(r10.ElectionError) as e:
        r10.lock_election(OFFICER, "e1")
    assert e.value.status == 403 and status() == "DRAFT"
    assert audit_log == ["ELECTION_LOCK_REFUSED"]


def test_cannot_lock_twice(app, audit_log):
    r10.lock_election(DELEGATE, "e1")
    with pytest.raises(r10.ElectionError) as e:
        r10.lock_election(DELEGATE, "e1")
    assert e.value.code == "ALREADY_LOCKED"


def test_cannot_lock_after_polls_open(app):
    add_election("e2", opens_in=timedelta(hours=-1))
    with pytest.raises(r10.ElectionError) as e:
        r10.lock_election(DELEGATE, "e2")
    assert e.value.code == "TOO_LATE"


def test_candidate_numbers_must_be_1_to_n(app):
    add_election("e3", positions=(1, 3))
    with pytest.raises(r10.ElectionError) as e:
        r10.lock_election(DELEGATE, "e3")
    assert e.value.code == "BAD_CANDIDATES"


# ------------------------------------------------------------------ tampering
@pytest.mark.parametrize("sql", [
    "UPDATE candidates SET name = 'Mallory' WHERE id = 'e1-c1'",
    "UPDATE candidates SET ballot_pos = 4 WHERE id = 'e1-c3'",
    "INSERT INTO candidates VALUES ('extra', 'e1', 'Extra', 'Party X', 4)",
    "DELETE FROM candidates WHERE id = 'e1-c2'",
    "UPDATE elections SET closes_at = '2099-01-01 00:00:00' WHERE id = 'e1'",
])
def test_any_change_after_locking_is_detected(app, audit_log, sql):
    r10.lock_election(DELEGATE, "e1")
    db.session.execute(text(sql))                 # SQLite has no triggers here, so this simulates bypassing them
    db.session.commit()
    assert r10.check_definition("e1")["valid"] is False


# ------------------------------------------------------------------ polls open / closed
def move_clock(monkeypatch, delta):
    later = r10.now() + delta
    monkeypatch.setattr("app.election.r10_lock.now", lambda: later)


def test_status_follows_the_locked_times_and_votes_only_while_open(app, audit_log, monkeypatch):
    r10.lock_election(DELEGATE, "e1")
    with pytest.raises(r10.ElectionError) as e:
        r10.require_polls_open("e1")                                 # locked, not open yet
    assert e.value.code == "POLLS_NOT_OPEN"

    move_clock(monkeypatch, timedelta(days=1, hours=1))
    r10.require_polls_open("e1")                                     # open: no error
    assert status() == "OPEN"

    move_clock(monkeypatch, timedelta(days=1, hours=11))
    with pytest.raises(r10.ElectionError):
        r10.require_polls_open("e1")                                 # closed: no more votes
    assert status() == "CLOSED"


def test_votes_stop_if_the_ballot_was_tampered_with(app, audit_log, monkeypatch):
    r10.lock_election(DELEGATE, "e1")
    move_clock(monkeypatch, timedelta(days=1, hours=1))
    db.session.execute(text("UPDATE candidates SET party = 'Other' WHERE id = 'e1-c1'"))
    db.session.commit()
    with pytest.raises(r10.ElectionError) as e:
        r10.require_polls_open("e1")
    assert e.value.code == "DEFINITION_TAMPERED" and "ELECTION_DEFINITION_TAMPERED" in audit_log


def test_draft_elections_never_open(app, monkeypatch):
    move_clock(monkeypatch, timedelta(days=1, hours=1))
    with pytest.raises(r10.ElectionError):
        r10.require_polls_open("e1")
    assert status() == "DRAFT"


# ------------------------------------------------------------------ routes
def signed_in(client, account_id):
    with client.session_transaction() as s:
        t = int(time.time())
        s.update(user_id=account_id, last_seen=t, mfa_user=account_id, mfa_at=t)


def test_http_lock_then_public_definition(app):
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    db.session.add_all([Account(id="u-delegate", email="d@evp.test", password_hash="x", role="delegate", status="ACTIVE"),
                        Account(id="u-officer", email="o@evp.test", password_hash="x", role="officer", status="ACTIVE")])
    db.session.commit()
    client = app.test_client()
    assert client.get("/election/e1/definition").status_code == 404              # not locked yet

    signed_in(client, "u-officer")
    assert client.post("/election/e1/lock").status_code == 403
    signed_in(client, "u-delegate")
    resp = client.post("/election/e1/lock")
    assert resp.status_code == 200 and resp.get_json()["status"] == "APPROVED"

    body = app.test_client().get("/election/e1/definition").get_json()          # public, no sign-in
    assert body["valid"] is True and body["public_key"] and len(body["definition"]["candidates"]) == 3
