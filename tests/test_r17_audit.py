"""R17 - tamper-proof activity log, and the real Ed25519 sign/verify it uses."""
import json
import time

import pytest
from sqlalchemy import text

from app import create_app
from app.audit.models import AuditEntry
from app.auth.models import Account
from app.common import crypto
from app.common.audit import GENESIS, audit, verify_log
from app.extensions import db


@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True, LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    with app.app_context():
        db.create_all()
        for id_, role in (("u-auditor", "auditor"), ("u-officer", "officer")):
            db.session.add(Account(id=id_, email=f"{role}@evp.test", password_hash="x", role=role, status="ACTIVE"))
        db.session.commit()
        yield app
        db.session.remove()


def three_entries():
    audit("ELECTION_CANDIDATE_ADDED", actor_id="u-officer", details={"candidate_id": "c1"})
    audit("ELECTION_EXCLUSION_APPROVED", actor_id="u-delegate", details={"exclusion_id": "x1"})
    audit("ELECTION_RESULTS_PUBLISHED", actor_id="u-counter", details={"election_id": "e1"})


def signed_in_as(client, account_id):
    with client.session_transaction() as s:
        now = int(time.time())
        s.update(user_id=account_id, last_seen=now, mfa_user=account_id, mfa_at=now)


# ------------------------------------------------------------------ signing
def test_sign_and_verify(app):
    sig = crypto.sign(b"result")
    assert crypto.verify(b"result", sig)
    assert not crypto.verify(b"result!", sig)
    assert not crypto.verify(b"result", "bm90IGEgc2lnbmF0dXJl")
    assert not crypto.verify(b"result", "not base64 at all")


# ------------------------------------------------------------------ the log
def test_entries_are_chained_and_signed(app):
    three_entries()
    rows = db.session.query(AuditEntry).order_by(AuditEntry.id).all()
    assert [r.event for r in rows] == ["ELECTION_CANDIDATE_ADDED", "ELECTION_EXCLUSION_APPROVED",
                                       "ELECTION_RESULTS_PUBLISHED"]
    assert rows[0].prev_hash == GENESIS
    assert rows[1].prev_hash == rows[0].entry_hash and rows[2].prev_hash == rows[1].entry_hash
    assert rows[0].actor_id == "u-officer" and json.loads(rows[0].details) == {"candidate_id": "c1"}
    assert verify_log() == {"valid": True, "entries": 3, "first_bad_entry": None, "problem": None}


def test_changing_who_did_it_is_caught(app):
    three_entries()
    db.session.execute(text("UPDATE audit_log SET actor_id = 'someone-else' WHERE id = 2"))
    result = verify_log()
    assert result["valid"] is False and result["first_bad_entry"] == 2


def test_changing_details_is_caught(app):
    three_entries()
    db.session.execute(text("""UPDATE audit_log SET details = '{"candidate_id":"c9"}' WHERE id = 1"""))
    assert verify_log()["first_bad_entry"] == 1


def test_deleting_an_entry_is_caught(app):
    three_entries()
    db.session.execute(text("DELETE FROM audit_log WHERE id = 2"))
    result = verify_log()
    assert result["valid"] is False and result["first_bad_entry"] == 3


def test_rewriting_a_row_and_its_hash_is_caught_by_the_signature(app):
    three_entries()
    row = db.session.get(AuditEntry, 3)
    row.details = '{"election_id":"e2"}'
    from app.common.audit import _content
    from app.common.crypto import chain_hash
    row.entry_hash = chain_hash(row.prev_hash, _content(row.event, row.actor_id, row.details, row.created_at))
    db.session.commit()
    result = verify_log()
    assert result["first_bad_entry"] == 3 and result["problem"] == "the signature does not match"


def test_real_actions_are_logged(app):
    app.test_client().post("/auth/login", json={"email": "officer@evp.test", "password": "Secret-Guess-42"})
    row = db.session.query(AuditEntry).order_by(AuditEntry.id.desc()).first()
    assert row.event == "AUTH_LOGIN_FAILED" and row.actor_id == "u-officer"
    assert "Secret-Guess-42" not in row.details                                     # never the password


# ------------------------------------------------------------------ routes
def test_auditor_can_check_and_read_the_log(app):
    three_entries()
    client = app.test_client()
    signed_in_as(client, "u-auditor")
    body = client.get("/audit/verify").get_json()
    assert body["valid"] is True and body["entries"] == 3 and body["public_key"]
    entries = client.get("/audit/entries?limit=2").get_json()
    assert [e["event"] for e in entries] == ["ELECTION_RESULTS_PUBLISHED", "ELECTION_EXCLUSION_APPROVED"]


def test_other_roles_and_signed_out_users_cannot_read_the_log(app):
    client = app.test_client()
    assert client.get("/audit/verify").status_code == 401
    signed_in_as(client, "u-officer")
    assert client.get("/audit/verify").status_code == 403
    assert client.get("/audit/entries").status_code == 403


def test_verify_command(app):
    three_entries()
    runner = app.test_cli_runner()
    assert "OK: all 3 entries are intact." in runner.invoke(args=["audit", "verify"]).output
    db.session.execute(text("UPDATE audit_log SET event = 'NOTHING_HAPPENED' WHERE id = 1"))
    db.session.commit()
    out = runner.invoke(args=["audit", "verify"])
    assert out.exit_code != 0 and "TAMPERED at entry 1" in out.output
