"""R6 - Confirmation code: signed, checkable, and with no preference data."""
import re

import pytest
from sqlalchemy import text

from app import create_app
from app.ballot import r04_ballot_box as box
from app.ballot import r05_crypto
from app.ballot import r06_receipt as receipt
from app.common.crypto import verify
from app.extensions import db
from tests.setd_helpers import add_election, create_ballot_tables, create_base_tables
from tests.test_r04_no_clues import FakeRedis

BATCH = 3
CHOICES = {"cand-alice": 1, "cand-bob": 2}


@pytest.fixture(scope="module")
def public_key():
    return r05_crypto.make_election_key()[0]


@pytest.fixture
def app(monkeypatch):
    app = create_app()
    app.config.update(TESTING=True, BALLOT_BATCH_SIZE=BATCH)
    with app.app_context():
        db.create_all()
        create_base_tables()
        create_ballot_tables()
        add_election("e1", "OPEN", ("cand-alice", "cand-bob"))
        add_election("e2", "OPEN", ("c3", "c4"))
        db.session.execute(text("UPDATE elections SET definition_fp = 'fp-' || id"))
        db.session.commit()
        fake = FakeRedis()
        monkeypatch.setattr("app.ballot.r04_ballot_box.get_redis", lambda: fake)
        monkeypatch.setattr("app.ballot.r06_receipt.get_redis", lambda: fake)
        monkeypatch.setattr("app.ballot.r04_ballot_box.require_polls_open", lambda election_id: None)
        monkeypatch.setattr("app.ballot.r04_ballot_box.audit", lambda *a, **k: None)
        yield app
        db.session.remove()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr("app.ballot.r06_receipt.audit", lambda event, actor_id, details: calls.append((event, details)))
    return calls


def cast(public_key, election_id="e1", choices=CHOICES):
    """What the casting route will do: seal on the voter's device, store (R4), hand back a receipt (R6)."""
    sealed = r05_crypto.seal_ballot(public_key, election_id, choices)
    return receipt.make_receipt(election_id, box.store_ballot(election_id, sealed))


def check(app, election_id, ballot_hash, signature):
    return app.test_client().post(f"/ballot/{election_id}/receipt/check",
                                  json={"ballot_hash": ballot_hash, "signature": signature})


# ---------------------------------------------------------------------- what is on a receipt
def test_a_receipt_shows_nothing_about_the_vote(app, public_key):
    r = cast(public_key)
    text_of_receipt = str(r).lower()
    for choice in CHOICES:
        assert choice not in text_of_receipt
    assert set(r) == {"election_id", "confirmation_code", "ballot_hash", "signature", "public_key", "note"}


def test_a_receipt_holds_no_voter_time_or_ip(app, public_key):
    r = cast(public_key)
    for word in ("voter", "user", "elector", "time", "date", "ip", "address"):
        assert not any(word in key for key in r)


def test_the_same_vote_gives_different_receipts(app, public_key):
    assert cast(public_key)["ballot_hash"] != cast(public_key)["ballot_hash"]       # fresh randomness in R5 sealing


def test_the_code_is_short_and_comes_from_the_ballot_hash(app, public_key):
    r = cast(public_key)
    assert re.fullmatch(r"[0-9A-F]{4}(-[0-9A-F]{4}){3}", r["confirmation_code"])
    assert r["confirmation_code"].replace("-", "").lower() == r["ballot_hash"][:16]


def test_the_receipt_is_signed_by_the_platform(app, public_key):
    r = cast(public_key)
    assert verify(receipt.receipt_message("e1", r["ballot_hash"]), r["signature"])
    assert not verify(receipt.receipt_message("e2", r["ballot_hash"]), r["signature"])      # tied to its election


def test_nothing_new_is_stored_for_a_receipt(app, public_key):
    tables_before = set(db.inspect(db.engines["ballot"]).get_table_names())
    for _ in range(BATCH):
        cast(public_key)
    assert set(db.inspect(db.engines["ballot"]).get_table_names()) == tables_before


# ---------------------------------------------------------------------------- checking it
def test_a_receipt_says_waiting_until_its_batch_is_written(app, public_key):
    r = cast(public_key)
    body = check(app, "e1", r["ballot_hash"], r["signature"]).get_json()
    assert body["signature_valid"] and body["status"] == "WAITING"


def test_a_receipt_says_in_ballot_box_after_the_batch_is_written(app, public_key):
    r = cast(public_key)
    box.flush_pending("e1")
    body = check(app, "e1", r["ballot_hash"], r["signature"]).get_json()
    assert body == {"election_id": "e1", "signature_valid": True, "confirmation_code": r["confirmation_code"],
                    "status": "IN_BALLOT_BOX"}


def test_a_full_batch_is_found_in_the_box(app, public_key):
    receipts = [cast(public_key) for _ in range(BATCH)]                 # the third one writes the batch
    for r in receipts:
        assert check(app, "e1", r["ballot_hash"], r["signature"]).get_json()["status"] == "IN_BALLOT_BOX"


def test_a_genuine_receipt_for_a_ballot_that_is_not_there_says_not_found(app):
    missing = "ab" * 32
    body = check(app, "e1", missing, receipt.make_receipt("e1", missing)["signature"]).get_json()
    assert body["signature_valid"] and body["status"] == "NOT_FOUND"


# ---------------------------------------------------------------------------- misuse
def test_a_forged_receipt_is_spotted_and_logged(app, public_key, audit_log):
    r = cast(public_key)
    forged = ("B" if r["signature"][0] != "B" else "C") + r["signature"][1:]
    body = check(app, "e1", r["ballot_hash"], forged).get_json()
    assert body["signature_valid"] is False and body["status"] == "FORGED"
    assert audit_log == [("BALLOT_RECEIPT_FORGED", {"election_id": "e1"})]


def test_a_receipt_cannot_be_moved_to_another_election(app, public_key, audit_log):
    r = cast(public_key)
    assert check(app, "e2", r["ballot_hash"], r["signature"]).get_json()["status"] == "FORGED"


def test_a_made_up_hash_with_a_real_signature_is_forged(app, public_key, audit_log):
    r = cast(public_key)
    assert check(app, "e1", "cd" * 32, r["signature"]).get_json()["status"] == "FORGED"


@pytest.mark.parametrize("body", [
    {},
    {"ballot_hash": "ab" * 32},
    {"signature": "A" * 86 + "=="},
    {"ballot_hash": "AB" * 32, "signature": "A" * 86 + "=="},           # upper case is not a hash we issue
    {"ballot_hash": "ab" * 31, "signature": "A" * 86 + "=="},           # too short
    {"ballot_hash": "zz" * 32, "signature": "A" * 86 + "=="},
    {"ballot_hash": "ab" * 32, "signature": "<script>"},
    {"ballot_hash": "ab" * 32, "signature": "A" * 86 + "==", "voter_id": "u1"},   # unknown field
    {"ballot_hash": 5, "signature": "A" * 86 + "=="},
])
def test_badly_formed_checks_are_refused(app, body):
    resp = app.test_client().post("/ballot/e1/receipt/check", json=body)
    assert resp.status_code == 400 and resp.get_json()["error"] == "VALIDATION_FAILED"


def test_an_oversized_election_id_is_refused(app):
    resp = check(app, "e" * 37, "ab" * 32, "A" * 86 + "==")
    assert resp.status_code == 400 and resp.get_json()["error"] == "BAD_ELECTION"


def test_the_check_never_returns_the_sealed_ballot(app, public_key):
    r = cast(public_key)
    box.flush_pending("e1")
    body = str(check(app, "e1", r["ballot_hash"], r["signature"]).get_json())
    assert '"ek"' not in body and "ciphertext" not in body
