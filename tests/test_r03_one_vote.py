"""R3 - One vote, every channel: one central register, one all-or-nothing step."""
import itertools

import pytest
from sqlalchemy import insert
from sqlalchemy.exc import IntegrityError

from app import create_app
from app.ballot import r03_register as r03
from app.ballot.r03_models import VoteRegister
from app.extensions import db
from tests.setd_helpers import USERS, add_account, add_election, create_base_tables, login_as

MODULE = "app.ballot.r03_register"
VOTER = USERS["voter"]["id"]
VOTER2 = USERS["voter2"]["id"]
OFFICER = USERS["officer"]


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        create_base_tables()
        add_election("e1", "OPEN", ("c1", "c2"))
        add_account(VOTER)
        add_account(VOTER2)
        yield app
        db.session.remove()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


def register_count(election="e1"):
    return db.session.query(VoteRegister).filter_by(election_id=election).count()


# --------------------------------------------------- one vote, whatever the channel
@pytest.mark.parametrize("first, second", list(itertools.product(r03.CHANNELS, r03.CHANNELS)))
def test_a_second_vote_is_refused_on_every_channel_after_a_first_on_any_channel(app, first, second):
    r03.mark_off(VOTER, "e1", first, actor_id="someone")
    with pytest.raises(r03.RegisterError) as e:
        r03.mark_off(VOTER, "e1", second, actor_id="someone")
    assert e.value.code == "ALREADY_VOTED" and e.value.status == 409
    assert register_count() == 1


def test_each_voter_and_each_election_has_their_own_one_vote(app):
    add_election("e2", "OPEN", ("d1", "d2"))
    r03.mark_off(VOTER, "e1", "IN_PERSON", "o1")
    r03.mark_off(VOTER2, "e1", "POSTAL", "o1")                     # another voter: fine
    r03.mark_off(VOTER, "e2", "ONLINE", VOTER)                     # another election: fine
    assert register_count("e1") == 2 and register_count("e2") == 1


def test_the_database_itself_refuses_a_second_row(app):
    """Not just a Python check: the primary key makes a duplicate impossible, even for code that skips our rules."""
    db.session.execute(insert(VoteRegister).values(election_id="e1", voter_id=VOTER, channel="POSTAL",
                                                   marked_by="x", marked_at=r03.now()))
    db.session.commit()
    with pytest.raises(IntegrityError):
        db.session.execute(insert(VoteRegister).values(election_id="e1", voter_id=VOTER, channel="ONLINE",
                                                       marked_by="y", marked_at=r03.now()))
    db.session.rollback()


def test_the_register_says_who_voted_not_how(app):
    columns = {c.name for c in VoteRegister.__table__.columns}
    assert columns == {"election_id", "voter_id", "channel", "marked_at", "marked_by"}


# ------------------------------------------------------------- all or nothing
def test_the_extra_step_runs_in_the_same_transaction_and_its_result_is_returned(app):
    seen = []
    result = r03.mark_off(VOTER, "e1", "ONLINE", VOTER, then=lambda: seen.append("pass signed") or "the pass")
    assert result == "the pass" and seen == ["pass signed"] and r03.has_voted(VOTER, "e1")


def test_if_the_extra_step_fails_the_voter_is_not_marked_off_and_can_try_again(app):
    def broken():
        raise RuntimeError("the signing service is down")
    with pytest.raises(RuntimeError):
        r03.mark_off(VOTER, "e1", "ONLINE", VOTER, then=broken)
    assert not r03.has_voted(VOTER, "e1") and register_count() == 0
    r03.mark_off(VOTER, "e1", "ONLINE", VOTER, then=lambda: "pass")                  # a retry works
    assert r03.has_voted(VOTER, "e1")


def test_a_failure_inside_the_extra_step_is_not_mistaken_for_a_double_vote(app):
    def clash():
        raise IntegrityError("x", {}, Exception("some other unique key"))
    with pytest.raises(IntegrityError):
        r03.mark_off(VOTER, "e1", "ONLINE", VOTER, then=clash)
    assert not r03.has_voted(VOTER, "e1")


# --------------------------------------------------------------- who and when
def test_voting_only_works_while_the_polls_are_open(app):
    for status in ("DRAFT", "APPROVED", "CLOSED"):
        add_election(f"x-{status}", status, (f"{status}-a",))
        with pytest.raises(r03.RegisterError) as e:
            r03.mark_off(VOTER, f"x-{status}", "IN_PERSON", "o1")
        assert e.value.code == "POLLS_NOT_OPEN"
    with pytest.raises(r03.RegisterError) as e:
        r03.mark_off(VOTER, "nope", "IN_PERSON", "o1")
    assert e.value.status == 404


@pytest.mark.parametrize("kind", ["unknown", "not a voter", "suspended", "pending"])
def test_only_an_active_voter_can_be_marked_off(app, kind):
    add_account("acc-officer", role="officer")
    add_account("acc-suspended", status="SUSPENDED")
    add_account("acc-pending", status="PENDING")
    voter_id = {"unknown": "nobody", "not a voter": "acc-officer", "suspended": "acc-suspended",
                "pending": "acc-pending"}[kind]
    with pytest.raises(r03.RegisterError) as e:
        r03.mark_off(voter_id, "e1", "IN_PERSON", "o1")
    assert e.value.code == "VOTER_NOT_FOUND" and register_count() == 0


def test_a_voter_enrolled_in_another_division_is_refused(app):
    add_account("acc-sydney", division="Sydney", state="NSW")
    add_account("acc-nodivision", division=None, state=None)
    for voter_id in ("acc-sydney", "acc-nodivision"):
        with pytest.raises(r03.RegisterError) as e:
            r03.mark_off(voter_id, "e1", "IN_PERSON", "o1")
        assert e.value.code == "WRONG_DIVISION" and e.value.status == 403
    assert register_count() == 0


def test_an_unknown_channel_is_refused(app):
    with pytest.raises(r03.RegisterError) as e:
        r03.mark_off(VOTER, "e1", "CARRIER_PIGEON", "o1")
    assert e.value.code == "INVALID_CHANNEL" and e.value.status == 400


def test_odd_text_in_the_voter_id_is_just_text(app):
    with pytest.raises(r03.RegisterError) as e:
        r03.mark_off("x' OR '1'='1", "e1", "IN_PERSON", "o1")
    assert e.value.code == "VOTER_NOT_FOUND" and register_count() == 0


# ------------------------------------------------------------------ officers
def test_an_officer_marks_a_voter_off_in_person_and_by_post(app, audit_log):
    r03.staff_mark_off(OFFICER, "e1", VOTER, "IN_PERSON")
    r03.staff_mark_off(OFFICER, "e1", VOTER2, "POSTAL")
    assert register_count() == 2 and audit_log[0][0] == "BALLOT_VOTER_MARKED_OFF"
    assert audit_log[0][1] == OFFICER["id"] and audit_log[0][2]["channel"] == "IN_PERSON"


def test_an_officer_cannot_mark_an_online_vote(app):
    with pytest.raises(r03.RegisterError) as e:
        r03.staff_mark_off(OFFICER, "e1", VOTER, "ONLINE")
    assert e.value.code == "INVALID_CHANNEL" and register_count() == 0


@pytest.mark.parametrize("who", ["voter", "admin", "counter", "delegate1", "custodian", "auditor"])
def test_only_an_officer_can_mark_a_voter_off_and_refusals_are_logged(app, audit_log, who):
    with pytest.raises(r03.RegisterError) as e:
        r03.staff_mark_off(USERS[who], "e1", VOTER, "IN_PERSON")
    assert e.value.status == 403 and register_count() == 0
    assert audit_log[-1][0] == "BALLOT_MARK_OFF_REFUSED" and audit_log[-1][1] == USERS[who]["id"]


def test_nobody_signed_in_cannot_mark_anyone_off(app, audit_log):
    with pytest.raises(r03.RegisterError):
        r03.staff_mark_off(None, "e1", VOTER, "IN_PERSON")
    assert audit_log[-1][1] == "anonymous"


def test_a_blocked_second_vote_is_logged_for_monitoring(app, audit_log):
    r03.staff_mark_off(OFFICER, "e1", VOTER, "IN_PERSON")
    with pytest.raises(r03.RegisterError):
        r03.mark_off(VOTER, "e1", "ONLINE", VOTER)                               # the same person tries online
    event, actor, details = audit_log[-1]
    assert event == "BALLOT_DOUBLE_VOTE_BLOCKED" and actor == VOTER
    assert details["attempted_channel"] == "ONLINE" and details["first_channel"] == "IN_PERSON"


# --------------------------------------------------------------------- HTTP
def test_http_officer_marks_a_voter_off_and_a_second_try_is_refused(app, monkeypatch):
    login_as(monkeypatch, "officer", MODULE)
    client = app.test_client()
    body = {"voter_id": VOTER, "channel": "IN_PERSON"}
    resp = client.post("/ballot/e1/mark-off", json=body)
    assert resp.status_code == 201 and resp.get_json() == {"election_id": "e1", "status": "MARKED_OFF"}
    resp = client.post("/ballot/e1/mark-off", json=dict(body, channel="POSTAL"))
    assert resp.status_code == 409 and resp.get_json()["error"] == "ALREADY_VOTED"
    assert set(resp.get_json()) == {"error", "message"}


def test_http_other_roles_are_refused(app, monkeypatch):
    login_as(monkeypatch, "voter", MODULE)
    resp = app.test_client().post("/ballot/e1/mark-off", json={"voter_id": VOTER, "channel": "IN_PERSON"})
    assert resp.status_code == 403 and register_count() == 0


def test_http_a_voter_sees_only_their_own_status(app, monkeypatch):
    client = app.test_client()
    login_as(monkeypatch, "voter", MODULE)
    assert client.get("/ballot/e1/my-status").get_json() == {"election_id": "e1", "voted": False}
    r03.staff_mark_off(OFFICER, "e1", VOTER, "POSTAL")
    assert client.get("/ballot/e1/my-status").get_json()["voted"] is True
    login_as(monkeypatch, "voter2", MODULE)                                      # someone else: their own answer
    assert client.get("/ballot/e1/my-status").get_json()["voted"] is False


def test_http_my_status_is_for_voters_only(app, monkeypatch):
    login_as(monkeypatch, "officer", MODULE)
    assert app.test_client().get("/ballot/e1/my-status").status_code == 403
