"""R12 - second sign-in step for everyone."""
import time
from datetime import timedelta

import pyotp
import pytest

from app import create_app
from app.auth import r12_mfa as r12
from app.auth.models import Account
from app.extensions import db
from tests.setd_helpers import USERS, add_election, create_base_tables, login_as

MODULE = "app.auth.r12_mfa"
R19 = "app.election.r19_exclusions"


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        for key in ("admin", "counter", "voter", "delegate1", "delegate2"):
            u = USERS[key]
            db.session.add(Account(id=u["id"], email=f"{key}@evp.test", password_hash="x",
                                   role=u["role"], status="ACTIVE"))
        db.session.commit()
        yield app
        db.session.remove()


@pytest.fixture
def emails(monkeypatch):
    sent = []
    monkeypatch.setattr(f"{MODULE}._send_email", lambda to, code: sent.append((to, code)))
    return sent


@pytest.fixture
def client(app):
    return app.test_client()


def set_up_app(monkeypatch, client, who="admin"):
    login_as(monkeypatch, who, MODULE)
    resp = client.post("/auth/mfa/setup")
    assert resp.status_code == 201
    return pyotp.TOTP(resp.get_json()["secret"])


# ------------------------------------------------------------ authenticator app (staff)
def test_setup_stores_the_secret_encrypted_and_only_once(app, client, monkeypatch):
    totp = set_up_app(monkeypatch, client)
    stored = db.session.get(Account, USERS["admin"]["id"]).mfa_secret_enc
    assert stored and totp.secret not in stored
    assert client.post("/auth/mfa/setup").get_json()["error"] == "MFA_ALREADY_SET_UP"


def test_correct_code_passes_and_marks_the_session(app, client, monkeypatch):
    totp = set_up_app(monkeypatch, client)
    resp = client.post("/auth/mfa/verify", json={"code": totp.now()})
    assert resp.status_code == 200 and resp.get_json() == {"status": "MFA_PASSED"}
    with client.session_transaction() as s:
        assert s["mfa_user"] == USERS["admin"]["id"]


def test_wrong_code_is_refused(app, client, monkeypatch):
    totp = set_up_app(monkeypatch, client)
    wrong = f"{(int(totp.now()) + 1) % 10 ** 6:06d}"
    resp = client.post("/auth/mfa/verify", json={"code": wrong})
    assert resp.status_code == 401 and resp.get_json()["error"] == "MFA_WRONG_CODE"


def test_a_code_cannot_be_used_twice(app, client, monkeypatch):
    totp = set_up_app(monkeypatch, client)
    code = totp.now()
    assert client.post("/auth/mfa/verify", json={"code": code}).status_code == 200
    assert client.post("/auth/mfa/verify", json={"code": code}).status_code == 401


def test_five_wrong_codes_lock_the_step_even_for_the_right_code(app, client, monkeypatch):
    totp = set_up_app(monkeypatch, client)
    wrong = f"{(int(totp.now()) + 1) % 10 ** 6:06d}"
    for _ in range(r12.MAX_FAILURES):
        client.post("/auth/mfa/verify", json={"code": wrong})
    resp = client.post("/auth/mfa/verify", json={"code": totp.now()})
    assert resp.status_code == 429 and resp.get_json()["error"] == "MFA_LOCKED"


def test_badly_formed_code_is_refused_by_validation(app, client, monkeypatch):
    set_up_app(monkeypatch, client)
    for bad in ("12ab56", "1234567", "", 123456):
        assert client.post("/auth/mfa/verify", json={"code": bad}).status_code == 400


def test_staff_have_no_exceptions(app, client, monkeypatch, emails):
    login_as(monkeypatch, "counter", MODULE)
    resp = client.post("/auth/mfa/verify", json={"code": "123456"})
    assert resp.status_code == 403 and resp.get_json()["error"] == "MFA_NOT_SET_UP"
    resp = client.post("/auth/mfa/email-code")
    assert resp.status_code == 403 and resp.get_json()["error"] == "EMAIL_CODE_NOT_ALLOWED"
    assert emails == []


def test_signed_out_is_refused(app, client, monkeypatch):
    login_as(monkeypatch, None, MODULE)
    assert client.post("/auth/mfa/verify", json={"code": "123456"}).status_code == 401


# ------------------------------------------------------------ emailed code (voters)
def test_voter_email_code_works_once(app, client, monkeypatch, emails):
    login_as(monkeypatch, "voter", MODULE)
    assert client.post("/auth/mfa/email-code").status_code == 200
    to, code = emails[-1]
    assert to == "voter@evp.test"
    assert client.post("/auth/mfa/verify", json={"code": code}).status_code == 200
    assert client.post("/auth/mfa/verify", json={"code": code}).status_code == 401


def test_voter_email_code_expires_after_five_minutes(app, client, monkeypatch, emails):
    login_as(monkeypatch, "voter", MODULE)
    client.post("/auth/mfa/email-code")
    code = emails[-1][1]
    later = r12.now() + timedelta(minutes=r12.EMAIL_CODE_MINUTES, seconds=1)
    monkeypatch.setattr(f"{MODULE}.now", lambda: later)
    assert client.post("/auth/mfa/verify", json={"code": code}).status_code == 401


def test_only_a_hash_of_the_emailed_code_is_stored(app, client, monkeypatch, emails):
    login_as(monkeypatch, "voter", MODULE)
    client.post("/auth/mfa/email-code")
    code = emails[-1][1]
    row = db.session.get(r12.MfaEmailCode, USERS["voter"]["id"])
    assert code not in row.code_hash


# ------------------------------------------------------------ @mfa_required
def test_mfa_required_refuses_without_a_fresh_step(app, client, monkeypatch):
    app.config["MFA_ENFORCE"] = True
    totp = set_up_app(monkeypatch, client)
    resp = client.get("/auth/mfa/readiness")
    assert resp.status_code == 401 and resp.get_json()["error"] == "MFA_REQUIRED"

    client.post("/auth/mfa/verify", json={"code": totp.now()})
    assert client.get("/auth/mfa/readiness").status_code == 200

    with client.session_transaction() as s:                     # 16 minutes later the step is no longer fresh
        s["mfa_at"] = int(time.time()) - 16 * 60
    assert client.get("/auth/mfa/readiness").status_code == 401


def test_r19_approval_needs_a_fresh_second_step(app, client, monkeypatch):
    app.config["MFA_ENFORCE"] = True
    create_base_tables()
    add_election("e1", "CLOSED", ("c1", "c2"))
    login_as(monkeypatch, "delegate1", R19)
    resp = client.post("/election/exclusions", json={"election_id": "e1", "candidate_id": "c1", "reason": "Court order"})
    exclusion_id = resp.get_json()["exclusion_id"]

    login_as(monkeypatch, "delegate2", R19)
    resp = client.post(f"/election/exclusions/{exclusion_id}/approve")
    assert resp.status_code == 401 and resp.get_json()["error"] == "MFA_REQUIRED"


# ------------------------------------------------------------ pre-election check
def test_readiness_lists_staff_without_the_app(app, client, monkeypatch):
    set_up_app(monkeypatch, client, "admin")
    resp = client.get("/auth/mfa/readiness")
    body = resp.get_json()
    assert resp.status_code == 200 and body["ready"] is False
    assert "counter@evp.test" in body["staff_without_mfa"]
    assert "admin@evp.test" not in body["staff_without_mfa"]
    assert "voter@evp.test" not in body["staff_without_mfa"]


def test_readiness_is_admin_only(app, client, monkeypatch):
    login_as(monkeypatch, "counter", MODULE)
    assert client.get("/auth/mfa/readiness").status_code == 403
