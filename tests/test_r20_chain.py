"""R20 - Tamper-resistant ballot box: hash chain over the ballots, signed head, append-only."""
import time
import uuid

import pytest
from sqlalchemy import text

from app import create_app
from app.auth.models import Account
from app.ballot import r04_ballot_box as box
from app.ballot import r20_chain as chain
from app.ballot.r20_models import BallotChainHead
from app.common.crypto import verify
from app.extensions import db
from tests.setd_helpers import add_election, create_ballot_tables, create_base_tables, store_sealed
from tests.test_r04_no_clues import FakeRedis

BATCH = 3


@pytest.fixture
def app(monkeypatch):
    app = create_app()
    app.config.update(TESTING=True, BALLOT_BATCH_SIZE=BATCH)
    with app.app_context():
        db.create_all()
        create_base_tables()
        create_ballot_tables()
        add_election("e1", "OPEN", ("c1", "c2"))
        add_election("e2", "OPEN", ("c3", "c4"))
        db.session.execute(text("UPDATE elections SET definition_fp = 'fp-' || id"))
        for id_, role in (("u-auditor", "auditor"), ("u-voter", "voter")):
            db.session.add(Account(id=id_, email=f"{role}@evp.test", password_hash="x", role=role, status="ACTIVE"))
        db.session.commit()
        fake = FakeRedis()
        monkeypatch.setattr("app.ballot.r04_ballot_box.get_redis", lambda: fake)
        monkeypatch.setattr("app.ballot.r04_ballot_box.require_polls_open", lambda election_id: None)
        monkeypatch.setattr("app.ballot.r04_ballot_box.audit", lambda *a, **k: None)
        yield app
        db.session.remove()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr("app.ballot.r20_chain.audit", lambda event, actor_id, details: calls.append((event, details)))
    return calls


def cast(n, election_id="e1"):
    """n ballots go through R4 (shuffled batches), then the last part-full batch is written."""
    for i in range(n):
        box.store_ballot(election_id, f'{{"c": "sealed-{election_id}-{i}"}}')
    box.flush_pending(election_id)


def in_chain_order(election_id="e1"):
    with db.engines["ballot"].connect() as c:
        rows = c.execute(text("SELECT * FROM ballots WHERE election_id = :eid"), {"eid": election_id}).mappings().all()
    by_prev, ordered, prev = {r["chain_prev"]: r for r in rows}, [], chain.GENESIS
    while prev in by_prev:
        ordered.append(by_prev[prev])
        prev = by_prev[prev]["chain_head"]
    return ordered


def ballot_sql(sql, **params):
    """An attacker with database access changes the ballot box directly."""
    with db.engines["ballot"].begin() as c:
        c.execute(text(sql), params)


def signed_in_as(client, account_id):
    with client.session_transaction() as s:
        now = int(time.time())
        s.update(user_id=account_id, last_seen=now, mfa_user=account_id, mfa_at=now)


# --------------------------------------------------------------------------- an honest box
def test_an_untouched_box_verifies(app):
    cast(7)                                                      # batches of 3, 3 and 1
    outcome = chain.verify_ballot_chain("e1")
    assert outcome["valid"] and outcome["length"] == 7 and outcome["problem"] is None


def test_every_ballot_is_one_link_of_a_single_chain(app):
    cast(7)
    ordered = in_chain_order()
    assert len(ordered) == 7 and ordered[0]["chain_prev"] == chain.GENESIS
    for before, after in zip(ordered, ordered[1:]):
        assert after["chain_prev"] == before["chain_head"]
    assert ordered[-1]["chain_head"] == db.session.get(BallotChainHead, "e1").head


def test_the_head_is_signed_with_the_platform_key(app):
    cast(4)
    row = db.session.get(BallotChainHead, "e1")
    assert row.length == 4
    assert verify(chain.head_message("e1", row.length, row.head), row.signature)
    assert not verify(chain.head_message("e1", row.length - 1, row.head), row.signature)


def test_each_election_has_its_own_chain(app):
    cast(4, "e1")
    cast(2, "e2")
    assert chain.verify_ballot_chain("e1")["length"] == 4 and chain.verify_ballot_chain("e2")["length"] == 2
    assert in_chain_order("e2")[0]["chain_prev"] == chain.GENESIS


def test_an_election_with_no_ballots_is_valid_and_empty(app):
    assert chain.verify_ballot_chain("e1") == {"election_id": "e1", "valid": True, "length": 0, "head": None,
                                               "problem": None, "bad_ballot": None}


# ------------------------------------------------------------------------------ tampering
def test_changing_a_sealed_ballot_is_caught(app):
    cast(6)
    victim = in_chain_order()[2]
    ballot_sql("UPDATE ballots SET ciphertext = :ct WHERE id = :id", ct=b'{"c": "forged"}', id=victim["id"])
    outcome = chain.verify_ballot_chain("e1")
    assert not outcome["valid"] and outcome["bad_ballot"] == victim["id"]
    assert outcome["problem"] == "a sealed ballot was changed"


def test_changing_a_ballot_and_its_hash_together_is_still_caught(app):
    import hashlib
    cast(6)
    victim, forged = in_chain_order()[2], b'{"c": "forged"}'
    ballot_sql("UPDATE ballots SET ciphertext = :ct, ballot_hash = :h WHERE id = :id",
               ct=forged, h=hashlib.sha256(forged).hexdigest(), id=victim["id"])
    outcome = chain.verify_ballot_chain("e1")
    assert not outcome["valid"] and outcome["problem"] == "a ballot's details were changed"


def test_moving_a_ballot_to_another_batch_is_caught(app):
    cast(6)
    victim = in_chain_order()[0]
    ballot_sql("UPDATE ballots SET batch_id = 'moved' WHERE id = :id", id=victim["id"])
    assert chain.verify_ballot_chain("e1")["problem"] == "a ballot's details were changed"


def test_removing_a_ballot_from_the_middle_is_caught(app):
    cast(6)
    ballot_sql("DELETE FROM ballots WHERE id = :id", id=in_chain_order()[3]["id"])
    outcome = chain.verify_ballot_chain("e1")
    assert not outcome["valid"] and "removed" in outcome["problem"]


def test_removing_the_newest_ballot_is_caught(app):
    cast(6)
    ballot_sql("DELETE FROM ballots WHERE id = :id", id=in_chain_order()[-1]["id"])
    outcome = chain.verify_ballot_chain("e1")
    assert not outcome["valid"] and "shorter" in outcome["problem"]


def test_slipping_in_a_ballot_without_a_link_is_caught(app):
    cast(3)
    store_sealed("e1", '{"c": "stuffed"}')                         # chain_prev is empty
    assert chain.verify_ballot_chain("e1")["problem"] == "a ballot was added that is not on the chain"


def test_slipping_in_a_ballot_that_copies_a_link_is_caught(app):
    cast(3)
    first = in_chain_order()[0]
    ballot_sql("INSERT INTO ballots (id, election_id, ciphertext, ballot_hash, definition_fp, batch_id, chain_prev, "
               "chain_head) VALUES (:id, 'e1', :ct, :h, 'fp-e1', 'x', :prev, :head)",
               id=uuid.uuid4().hex, ct=first["ciphertext"], h=first["ballot_hash"],
               prev=first["chain_prev"], head=first["chain_head"])
    assert chain.verify_ballot_chain("e1")["problem"] == "a ballot was added that is not on the chain"


def test_adding_a_correctly_linked_ballot_after_the_head_is_caught(app):
    import hashlib
    cast(3)
    tip, ct, new_id = in_chain_order()[-1]["chain_head"], b'{"c": "stuffed"}', uuid.uuid4().hex
    h = hashlib.sha256(ct).hexdigest()
    head = chain.chain_hash(tip, chain.link_content(new_id, "e1", h, "fp-e1", "x"))
    ballot_sql("INSERT INTO ballots (id, election_id, ciphertext, ballot_hash, definition_fp, batch_id, chain_prev, "
               "chain_head) VALUES (:id, 'e1', :ct, :h, 'fp-e1', 'x', :prev, :head)",
               id=new_id, ct=ct, h=h, prev=tip, head=head)
    assert chain.verify_ballot_chain("e1")["problem"] == "a ballot was added after the signed head"


def test_rewriting_the_head_without_the_key_is_caught(app):
    cast(3)
    ballot_sql("UPDATE ballot_chain_heads SET length = 2 WHERE election_id = 'e1'")
    assert chain.verify_ballot_chain("e1")["problem"] == "the signed head was changed"


def test_ballots_with_no_head_at_all_are_caught(app):
    store_sealed("e1", '{"c": "stuffed"}')
    assert not chain.verify_ballot_chain("e1")["valid"]


# ------------------------------------------------------------------ saved together or not at all
def test_a_failed_batch_write_does_not_move_the_head(app, monkeypatch):
    cast(3)
    before = db.session.get(BallotChainHead, "e1").head
    monkeypatch.setattr(box, "new_ballot_id", lambda: "a" * 32)    # two ballots with one id: the insert fails
    with pytest.raises(Exception):
        cast(BATCH)
    db.session.expire_all()
    assert db.session.get(BallotChainHead, "e1").head == before
    assert chain.verify_ballot_chain("e1")["valid"]


def test_the_database_schema_makes_ballots_append_only():
    from pathlib import Path
    sql = (Path(__file__).resolve().parent.parent / "db" / "init" / "30_setC_r20_ballot_chain.sql").read_text()
    assert "BEFORE UPDATE ON ballots" in sql and "BEFORE DELETE ON ballots" in sql


# ----------------------------------------------------------------------------- web routes
def test_anyone_can_fetch_and_check_the_signed_head(app):
    cast(4)
    body = app.test_client().get("/ballot/e1/chain").get_json()
    assert body["length"] == 4 and verify(body["signed_message"].encode(), body["signature"])
    assert body["public_key"] and "ciphertext" not in str(body)


def test_no_head_before_any_ballot_is_stored(app):
    resp = app.test_client().get("/ballot/e1/chain")
    assert resp.status_code == 404 and resp.get_json()["error"] == "NOT_FOUND"


def test_an_oversized_election_id_is_refused(app):
    assert app.test_client().get("/ballot/" + "e" * 37 + "/chain").status_code == 400


def test_an_auditor_can_run_the_full_check(app):
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    cast(4)
    client = app.test_client()
    signed_in_as(client, "u-auditor")
    body = client.get("/ballot/e1/chain/verify").get_json()
    assert body["valid"] and body["length"] == 4


def test_voters_and_signed_out_users_cannot_run_the_full_check(app):
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    client = app.test_client()
    assert client.get("/ballot/e1/chain/verify").status_code == 401
    signed_in_as(client, "u-voter")
    assert client.get("/ballot/e1/chain/verify").status_code == 403


def test_a_failed_check_is_written_to_the_activity_log(app, audit_log):
    cast(3)
    ballot_sql("DELETE FROM ballots WHERE id = :id", id=in_chain_order()[0]["id"])
    app.test_client().get("/ballot/e1/chain/verify")
    assert audit_log and audit_log[-1][0] == "BALLOT_CHAIN_TAMPERED"
    assert audit_log[-1][1]["election_id"] == "e1"


def test_verify_chain_command(app):
    cast(3)
    runner = app.test_cli_runner()
    assert "OK: all 3 ballots of e1 are intact." in runner.invoke(args=["ballot", "verify-chain", "e1"]).output
    ballot_sql("DELETE FROM ballots WHERE id = :id", id=in_chain_order()[1]["id"])
    out = runner.invoke(args=["ballot", "verify-chain", "e1"])
    assert out.exit_code != 0 and "TAMPERED" in out.output
