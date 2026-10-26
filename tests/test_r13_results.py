"""R13 - Signed results: publishing signs the result, anyone can check it, any change is caught."""
import base64
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import create_app
from app.auth.r14_models import AccessGrant, now
from app.common import crypto as shared_crypto
from app.election import r13_results as r13
from app.election.r07_count import canonical
from app.election.r07_models import CountResult
from app.extensions import db
from tests.setd_helpers import USERS, login_as

MODULE = "app.election.r13_results"
PAYLOAD = {"election_id": "e1", "winner": "c2", "ballots_counted": 9, "rounds": []}


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()


@pytest.fixture
def real_crypto(monkeypatch):
    """Real Ed25519 for these tests, so they do not depend on the shared sign/verify being finished."""
    key = Ed25519PrivateKey.generate()
    public = key.public_key()

    def fake_sign(data):
        return base64.b64encode(key.sign(data)).decode()

    def fake_verify(data, signature):
        try:
            public.verify(base64.b64decode(signature), data)
            return True
        except (InvalidSignature, ValueError):
            return False

    monkeypatch.setattr(f"{MODULE}.sign", fake_sign)
    monkeypatch.setattr(f"{MODULE}.verify", fake_verify)


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


def counted(payload=None, election_id="e1"):
    row = CountResult(election_id=election_id, payload_json=canonical(payload or PAYLOAD).decode(), counted_by="u1")
    db.session.add(row)
    db.session.commit()
    return row


def give_access(who="counter", scope="results"):
    db.session.add(AccessGrant(requester_id=USERS[who]["id"], ticket_no="INC-2", reason="Publish", scope=scope,
                               status="APPROVED", approver_id="user-admin-1", approved_at=now(),
                               expires_at=now() + timedelta(hours=4)))
    db.session.commit()


# --------------------------------------------------------------- publishing
def test_publish_signs_and_logs(app, real_crypto, audit_log):
    row = counted()
    published = r13.publish_result(USERS["counter"], "e1")
    assert published.signature and published.published_at is not None
    assert db.session.get(CountResult, row.id).signature == published.signature
    assert audit_log[-1][0] == "ELECTION_RESULTS_PUBLISHED"


def test_nothing_to_publish_before_a_count(app, real_crypto):
    with pytest.raises(r13.ResultError) as e:
        r13.publish_result(USERS["counter"], "e1")
    assert e.value.code == "NO_RESULT" and e.value.status == 409


def test_a_result_is_published_only_once(app, real_crypto):
    counted()
    r13.publish_result(USERS["counter"], "e1")
    with pytest.raises(r13.ResultError) as e:
        r13.publish_result(USERS["counter"], "e1")
    assert e.value.code == "ALREADY_PUBLISHED"


@pytest.mark.parametrize("who", ["voter", "delegate1", "custodian", "auditor"])
def test_only_counting_officers_and_admins_publish(app, real_crypto, who):
    counted()
    with pytest.raises(r13.ResultError) as e:
        r13.publish_result(USERS[who], "e1")
    assert e.value.status == 403


def test_an_admin_can_publish_too(app, real_crypto):
    counted()
    assert r13.publish_result(USERS["admin"], "e1").signature


def test_a_refused_publish_is_logged(app, real_crypto, audit_log):
    counted()
    with pytest.raises(r13.ResultError):
        r13.publish_result(USERS["voter"], "e1")
    event, actor, details = audit_log[-1]
    assert event == "ELECTION_RESULTS_REFUSED" and actor == USERS["voter"]["id"]


def test_two_people_publishing_at_the_same_moment_only_one_wins(app, real_crypto, monkeypatch):
    row = counted()
    stale = SimpleNamespace(id=row.id, payload_json=row.payload_json, published_at=None, election_id="e1")
    first = r13.publish_result(USERS["counter"], "e1")
    first_signature = first.signature
    class FakeQuery:
        def filter_by(self, **k): return self
        def order_by(self, *a): return self
        def first(self): return stale
    monkeypatch.setattr(r13.db.session, "query", lambda *a: FakeQuery())                  # the late one sees 'unpublished'
    with pytest.raises(r13.ResultError) as e:
        r13.publish_result(USERS["admin"], "e1")
    assert e.value.code == "ALREADY_PUBLISHED"
    monkeypatch.undo()
    assert db.session.get(CountResult, row.id).signature == first_signature


# ----------------------------------------------------------------- checking
def test_published_result_checks_out(app, real_crypto):
    counted()
    r13.publish_result(USERS["counter"], "e1")
    out = r13.published_result("e1")
    assert out["result"] == PAYLOAD and out["signature_valid"] is True


def test_changing_the_result_after_signing_is_caught(app, real_crypto):
    row = counted()
    r13.publish_result(USERS["counter"], "e1")
    changed = dict(PAYLOAD, winner="c1")                           # someone edits the winner in the database
    db.session.get(CountResult, row.id).payload_json = canonical(changed).decode()
    db.session.commit()
    assert r13.published_result("e1")["signature_valid"] is False


def test_changing_the_signature_is_caught(app, real_crypto):
    row = counted()
    r13.publish_result(USERS["counter"], "e1")
    db.session.get(CountResult, row.id).signature = base64.b64encode(b"x" * 64).decode()
    db.session.commit()
    assert r13.published_result("e1")["signature_valid"] is False


def test_unpublished_results_are_not_visible(app, real_crypto):
    counted()
    with pytest.raises(r13.ResultError) as e:
        r13.published_result("e1")
    assert e.value.status == 404


# --------------------------------------------------------------------- HTTP
def test_publish_route_needs_r14_access_for_results(app, real_crypto, monkeypatch):
    counted()
    login_as(monkeypatch, "counter", MODULE, "app.auth.r14_elevation")
    client = app.test_client()
    assert client.post("/election/e1/results/publish").status_code == 403           # no access yet
    give_access("counter", "counting")                                              # wrong scope
    assert client.post("/election/e1/results/publish").status_code == 403
    give_access("counter", "results")
    assert client.post("/election/e1/results/publish").status_code == 200


def test_anyone_can_read_and_check_a_published_result(app, real_crypto, monkeypatch):
    counted()
    login_as(monkeypatch, "counter", MODULE, "app.auth.r14_elevation")
    give_access()
    client = app.test_client()
    client.post("/election/e1/results/publish")
    login_as(monkeypatch, None, MODULE, "app.auth.r14_elevation")                   # a stranger, signed out
    body = client.get("/election/e1/results").get_json()
    assert body["signature_valid"] is True and body["result"]["winner"] == "c2"
    assert json.dumps(body["result"], sort_keys=True, separators=(",", ":")).encode() == canonical(PAYLOAD)


def test_unpublished_result_is_404_over_http(app):
    resp = app.test_client().get("/election/e1/results")
    assert resp.status_code == 404 and resp.get_json()["error"] == "NOT_PUBLISHED"


@pytest.mark.skipif(shared_crypto.sign(b"x") == "stub-signature",
                    reason="Turn on when R10 (the real sign/verify in common/crypto.py) is merged")
def test_works_with_the_shared_sign_and_verify(app):
    counted()
    r13.publish_result(USERS["counter"], "e1")
    assert r13.published_result("e1")["signature_valid"] is True
