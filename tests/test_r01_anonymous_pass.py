"""R1 - Voting anonymously: blind-signed voting pass, separate issuer and checker, count reconciliation.

R4's store_ballot and flush_pending are replaced by a small fake ballot box (they need Redis and R10's signed
election; their own tests cover them). Acting as a user works like the other tests: current_user is replaced.
"""
import hashlib
import secrets
import time

import pytest
from sqlalchemy import inspect, text

from app import create_app
from app.auth.models import Account
from app.ballot import r01_blind as blind
from app.ballot import r01_checker as checker
from app.ballot import r01_issuer as issuer
from app.ballot import r01_reconcile as reconcile
from app.ballot.r01_models import SpentPass
from app.ballot.r03_register import has_voted
from app.ballot.r04_ballot_box import BallotBoxError
from app.election.r10_lock import ElectionError
from app.extensions import db

VOTER = {"id": "u-voter-1", "role": "voter", "division": "Melbourne", "state": "VIC"}
VOTER2 = {"id": "u-voter-2", "role": "voter", "division": "Melbourne", "state": "VIC"}
AUDITOR = {"id": "u-auditor-1", "role": "auditor", "division": None, "state": None}
OFFICER = {"id": "u-officer-1", "role": "officer", "division": "Melbourne", "state": "VIC"}


class FakeBallotBox:
    def __init__(self):
        self.stored, self.fail_with = [], None

    def store(self, election_id, sealed):
        if self.fail_with:
            raise self.fail_with
        self.stored.append((election_id, sealed))
        with db.engines["ballot"].begin() as c:
            c.execute(text("INSERT INTO ballots (id, election_id) VALUES (:id, :e)"),
                      {"id": secrets.token_hex(16), "e": election_id})
        return hashlib.sha256(sealed.encode()).hexdigest()


@pytest.fixture
def app(monkeypatch):
    app = create_app()
    app.config.update(TESTING=True)
    with app.app_context():
        db.create_all()
        db.session.execute(text("CREATE TABLE elections (id TEXT PRIMARY KEY, name TEXT, division TEXT, "
                                "state TEXT, definition_fp TEXT, status TEXT)"))
        for eid, status in (("e1", "OPEN"), ("e2", "OPEN")):
            db.session.execute(text("INSERT INTO elections (id, name, division, state, status) "
                                    "VALUES (:id, 'Test', 'Melbourne', 'VIC', :s)"), {"id": eid, "s": status})
        with db.engines["ballot"].begin() as c:
            c.execute(text("CREATE TABLE ballots (id TEXT PRIMARY KEY, election_id TEXT)"))
        for user in (VOTER, VOTER2):
            db.session.add(Account(id=user["id"], email=f"{user['id']}@evp.test", password_hash="x", role="voter",
                                   division="Melbourne", state="VIC", status="ACTIVE"))
        db.session.commit()
        yield app
        db.session.remove()


@pytest.fixture
def box(monkeypatch):
    fake = FakeBallotBox()
    monkeypatch.setattr("app.ballot.r01_checker.store_ballot", fake.store)
    monkeypatch.setattr("app.ballot.r01_reconcile.flush_pending", lambda election_id: 0)
    return fake


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    record = lambda event, actor_id, details: calls.append((event, actor_id, details))
    for module in ("app.ballot.r01_checker", "app.ballot.r01_reconcile", "app.ballot.r03_register"):
        monkeypatch.setattr(f"{module}.audit", record)
    return calls


@pytest.fixture
def client(app):
    return app.test_client()


def act_as(monkeypatch, user):
    monkeypatch.setattr("app.ballot.r01_issuer.current_user", lambda: user)
    monkeypatch.setattr("app.ballot.r01_reconcile.current_user", lambda: user)


class VoterDevice:
    """What the voter's browser does: make a secret token, blind it, unblind the answer."""

    def __init__(self, client, election_id="e1"):
        self.client, self.election_id = client, election_id
        key = client.get(f"/ballot/{election_id}/pass-key").get_json()
        self.n, self.e = int(key["n"], 16), key["e"]
        self.token = secrets.token_bytes(32)
        self.m = blind.full_domain_hash(election_id, self.token, self.n)
        self.blinded, self.r = blind.blind(self.m, self.n, self.e)

    def get_pass(self):
        resp = self.client.post(f"/ballot/{self.election_id}/pass", json={"blinded": format(self.blinded, "x")})
        if resp.status_code == 201:
            self.signature = blind.unblind(int(resp.get_json()["blind_signature"], 16), self.r, self.n)
        return resp

    def cast(self, sealed="sealed-ballot-text", election_id=None, token=None, signature=None):
        return self.client.post(f"/ballot/{election_id or self.election_id}/cast", json={
            "token": (token or self.token).hex(), "signature": format(signature or self.signature, "x"),
            "sealed_ballot": sealed})


# ---------------------------------------------------------------- the whole anonymous journey
def test_a_voter_gets_a_pass_and_casts_a_ballot(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    assert device.get_pass().status_code == 201
    assert has_voted(VOTER["id"], "e1")                               # marked off when the pass is issued
    resp = device.cast()
    assert resp.status_code == 201 and resp.get_json()["accepted"] is True
    assert box.stored == [("e1", "sealed-ballot-text")]


def test_the_issuer_never_sees_the_pass(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    assert device.blinded != device.m                                 # what the issuer saw is not the pass
    assert device.token.hex() not in str(device.blinded) and device.token.hex() not in format(device.blinded, "x")
    assert blind.verify(device.m, device.signature, device.n)         # ... yet the signature fits the real pass


def test_nothing_on_the_ballot_side_identifies_the_voter(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    device.cast()
    columns = {c["name"] for c in inspect(db.engines["ballot"]).get_columns("spent_passes")}
    assert columns == {"token_hash", "election_id"}                  # no voter, time or IP
    stored = db.session.query(SpentPass).one()
    assert VOTER["id"] not in (stored.token_hash, stored.election_id)
    cast_events = [c for c in audit_log if c[0].startswith("BALLOT_PASS")]
    assert cast_events == []                                          # a good ballot leaves no log entry


def test_the_checker_never_asks_who_is_voting(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    assert not hasattr(checker, "current_user")                       # the checker cannot even look
    assert device.cast().status_code == 201


def test_casting_works_without_signing_in(app, client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)          # real checks on, nobody signed in
    assert app.test_client().post("/ballot/e1/cast", json={
        "token": device.token.hex(), "signature": format(device.signature, "x"),
        "sealed_ballot": "x"}).status_code == 201


# ---------------------------------------------------------------- one pass per voter (with R3)
def test_a_voter_gets_only_one_pass(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    VoterDevice(client).get_pass()
    second = VoterDevice(client).get_pass()
    assert second.status_code == 409 and second.get_json()["error"] == "ALREADY_VOTED"


def test_no_pass_for_someone_already_marked_off_in_person(client, box, audit_log, monkeypatch):
    from app.ballot.r03_register import staff_mark_off
    staff_mark_off(OFFICER, "e1", VOTER["id"], "IN_PERSON")
    act_as(monkeypatch, VOTER)
    assert VoterDevice(client).get_pass().status_code == 409


def test_if_signing_fails_the_voter_is_not_marked_off(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    def broken(*args):
        raise RuntimeError("signing failed")
    monkeypatch.setattr("app.ballot.r01_issuer.sign_blinded", broken)
    with pytest.raises(RuntimeError):
        VoterDevice(client).get_pass()
    assert not has_voted(VOTER["id"], "e1")                           # all or nothing


@pytest.mark.parametrize("value", ["0", "1"])
def test_a_meaningless_blinded_value_is_refused_and_nothing_is_marked(client, box, audit_log, monkeypatch, value):
    act_as(monkeypatch, VOTER)
    resp = client.post("/ballot/e1/pass", json={"blinded": value})
    assert resp.status_code == 400 and not has_voted(VOTER["id"], "e1")


def test_only_voters_get_passes(app, box, audit_log):
    with pytest.raises(issuer.PassError) as e:
        issuer.issue_voting_pass(OFFICER, "e1", "abc")
    assert e.value.status == 403


def test_no_pass_when_polls_are_closed(client, box, audit_log, monkeypatch):
    db.session.execute(text("UPDATE elections SET status = 'CLOSED' WHERE id = 'e1'"))
    db.session.commit()
    act_as(monkeypatch, VOTER)
    assert VoterDevice(client).get_pass().get_json()["error"] == "POLLS_NOT_OPEN"


# ---------------------------------------------------------------- the checker refuses bad passes
def test_a_pass_works_only_once(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    device.cast()
    again = device.cast(sealed="a second ballot")
    assert again.status_code == 409 and again.get_json()["error"] == "PASS_ALREADY_USED"
    assert len(box.stored) == 1
    assert audit_log[-1] == ("BALLOT_PASS_REUSE_BLOCKED", "anonymous", {"election_id": "e1"})


def test_a_forged_signature_is_refused(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    resp = device.cast(signature=device.signature + 1)
    assert resp.status_code == 403 and resp.get_json()["error"] == "PASS_INVALID" and box.stored == []


def test_a_made_up_pass_is_refused(client, box, audit_log):
    device = VoterDevice(client)                                     # never asked the issuer
    resp = device.cast(signature=secrets.randbelow(device.n))
    assert resp.status_code == 403 and box.stored == []


def test_a_signature_cannot_be_moved_to_another_token(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    assert device.cast(token=secrets.token_bytes(32)).status_code == 403


def test_a_pass_for_one_election_does_not_work_in_another(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client, "e1")
    device.get_pass()
    VoterDevice(client, "e2")                                         # e2 gets its own key
    assert device.cast(election_id="e2").status_code == 403


def test_if_the_ballot_box_refuses_the_pass_is_not_used_up(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    box.fail_with = ElectionError("POLLS_NOT_OPEN", "Voting is not open for this election.", 409)
    assert device.cast().status_code == 409
    assert db.session.query(SpentPass).count() == 0
    box.fail_with = None
    assert device.cast().status_code == 201                           # the voter can try again


def test_a_ballot_box_problem_is_passed_on(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    box.fail_with = BallotBoxError("BAD_BALLOT", "The sealed ballot is missing or too large.", 400)
    assert device.cast().get_json()["error"] == "BAD_BALLOT"


@pytest.mark.parametrize("body", [
    {"token": "zz" * 32, "signature": "ab", "sealed_ballot": "x"},                   # not hex
    {"token": "ab" * 31, "signature": "ab", "sealed_ballot": "x"},                   # too short
    {"token": "ab" * 32, "signature": "ab", "sealed_ballot": "x", "voter_id": "u-voter-1"},   # no extra fields
])
def test_bad_cast_requests_are_refused(client, box, audit_log, body):
    assert client.post("/ballot/e1/cast", json=body).status_code == 400 and box.stored == []


# ---------------------------------------------------------------- the counts must agree
def close_polls():
    db.session.execute(text("UPDATE elections SET status = 'CLOSED' WHERE id = 'e1'"))
    db.session.commit()


def test_counts_agree_after_a_normal_election(client, box, audit_log, monkeypatch):
    for voter in (VOTER, VOTER2):
        act_as(monkeypatch, voter)
        device = VoterDevice(client)
        device.get_pass()
        device.cast()
    VoterDevice(client)                                               # (no effect on counts)
    close_polls()
    act_as(monkeypatch, AUDITOR)
    assert client.get("/ballot/e1/passes/reconcile").get_json() == \
        {"issued": 2, "used": 2, "stored": 2, "match": True}


def test_an_unused_pass_is_fine(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    VoterDevice(client).get_pass()                                    # got a pass, never voted
    close_polls()
    body, _ = reconcile.reconcile(AUDITOR, "e1")
    assert body == {"issued": 1, "used": 0, "stored": 0, "match": True}


def test_an_extra_ballot_in_the_box_is_detected(client, box, audit_log, monkeypatch):
    act_as(monkeypatch, VOTER)
    device = VoterDevice(client)
    device.get_pass()
    device.cast()
    with db.engines["ballot"].begin() as c:                           # someone slips in a ballot directly
        c.execute(text("INSERT INTO ballots (id, election_id) VALUES ('stuffed', 'e1')"))
    close_polls()
    body, _ = reconcile.reconcile(AUDITOR, "e1")
    assert body["match"] is False and body["stored"] == 2
    assert audit_log[-1][0] == "PASS_COUNT_MISMATCH"


def test_reconcile_is_for_auditors_after_polls_close(client, box, audit_log):
    assert reconcile.reconcile(VOTER, "e1")[1] == 403
    assert reconcile.reconcile(AUDITOR, "e1")[1] == 409                # polls still open


# ---------------------------------------------------------------- the real sign-in checks
def test_getting_a_pass_needs_sign_in_and_mfa(app, client, box):
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    assert client.post("/ballot/e1/pass", json={"blinded": "abcdef"}).status_code == 401
    with client.session_transaction() as s:                          # password step only, no MFA
        s["user_id"], s["last_seen"] = VOTER["id"], int(time.time())
    assert client.post("/ballot/e1/pass", json={"blinded": "abcdef"}).status_code == 401
