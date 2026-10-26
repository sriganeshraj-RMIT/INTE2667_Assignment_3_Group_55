"""R8 - Access security: password sign-in, protected session cookie, 5-minute idle timeout,
temporary staff disabled after their contract or 30 days unused."""
import time
from datetime import date, timedelta

import pytest
from argon2 import PasswordHasher
from flask import jsonify

from app import create_app
from app.auth import r08_access as r08
from app.auth.models import Account
from app.extensions import db

PASSWORD = "correct horse battery staple"
HASH = PasswordHasher().hash(PASSWORD)


def add(id_, email, role="officer", status="ACTIVE", contract_end=None, last_login=None):
    db.session.add(Account(id=id_, email=email, password_hash=HASH, role=role, status=status,
                           contract_end=contract_end, last_login=last_login, created_at=r08.now()))
    db.session.commit()


@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True, LOGIN_ENFORCE=True)

    @app.get("/_t/private")
    def private():
        from app.common.auth import login_required
        return login_required(lambda: jsonify(ok=True))()

    @app.get("/_t/admin-only")
    def admin_only():
        from app.common.auth import role_required
        return role_required("admin")(lambda: jsonify(ok=True))()

    with app.app_context():
        db.create_all()
        add("u-officer", "officer@evp.test")
        add("u-admin", "admin@evp.test", role="admin")
        add("u-voter", "voter@evp.test", role="voter")
        yield app
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


def sign_in(client, email="officer@evp.test", password=PASSWORD):
    return client.post("/auth/login", json={"email": email, "password": password})


def pass_mfa(client):
    with client.session_transaction() as s:
        s["mfa_user"], s["mfa_at"] = s["user_id"], int(time.time())


# ------------------------------------------------------------------ password step
def test_correct_password_starts_a_session_and_asks_for_the_second_step(client):
    resp = sign_in(client)
    assert resp.status_code == 200 and resp.get_json() == {"status": "MFA_REQUIRED", "next": "setup"}
    assert sign_in(client, "voter@evp.test").get_json()["next"] == "email"


def test_wrong_password_and_unknown_email_get_the_same_answer(client):
    a = sign_in(client, password="wrong password")
    b = sign_in(client, email="nobody@evp.test")
    assert a.status_code == b.status_code == 401
    assert a.get_json() == b.get_json() == {"error": "LOGIN_FAILED", "message": r08.WRONG}


def test_a_password_alone_is_not_enough(client):
    sign_in(client)
    assert client.get("/_t/private").status_code == 401
    pass_mfa(client)
    assert client.get("/_t/private").status_code == 200


def test_signed_out_requests_are_refused(client):
    resp = client.get("/_t/private")
    assert resp.status_code == 401 and resp.get_json()["error"] == "NOT_SIGNED_IN"


def test_role_required_refuses_the_wrong_role(client):
    sign_in(client)
    pass_mfa(client)
    assert client.get("/_t/admin-only").status_code == 403
    sign_in(client, "admin@evp.test")
    pass_mfa(client)
    assert client.get("/_t/admin-only").status_code == 200


def test_signing_in_throws_away_the_old_session(client):
    with client.session_transaction() as s:
        s["planted"] = "by an attacker"
    sign_in(client)
    with client.session_transaction() as s:
        assert "planted" not in s and s["user_id"] == "u-officer"


def test_suspended_account_cannot_sign_in(app, client):
    db.session.get(Account, "u-officer").status = "SUSPENDED"
    db.session.commit()
    assert sign_in(client).status_code == 403


def test_disabled_account_stops_working_mid_session(app, client):
    sign_in(client)
    pass_mfa(client)
    db.session.get(Account, "u-officer").status = "DISABLED"
    db.session.commit()
    assert client.get("/_t/private").status_code == 401


def test_logout_ends_the_session(client):
    sign_in(client)
    pass_mfa(client)
    client.post("/auth/logout")
    assert client.get("/_t/private").status_code == 401


# ------------------------------------------------------------------ cookie and idle timeout
def test_session_cookie_is_protected_from_scripts_and_other_sites(client):
    cookie = sign_in(client).headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Strict" in cookie


def test_five_minutes_idle_signs_you_out(client):
    sign_in(client)
    pass_mfa(client)
    assert client.get("/_t/private").status_code == 200
    with client.session_transaction() as s:
        s["last_seen"] = int(time.time()) - (5 * 60 + 1)
    assert client.get("/_t/private").status_code == 401


def test_activity_keeps_the_session_alive(client):
    sign_in(client)
    pass_mfa(client)
    with client.session_transaction() as s:
        s["last_seen"] = int(time.time()) - 4 * 60
    assert client.get("/_t/private").status_code == 200


# ------------------------------------------------------------------ temporary staff
def test_temp_staff_past_contract_end_is_disabled_at_sign_in(app, client):
    add("u-temp", "temp@evp.test", contract_end=date.today() - timedelta(days=1))
    resp = sign_in(client, "temp@evp.test")
    assert resp.status_code == 403 and resp.get_json()["error"] == "ACCOUNT_DISABLED"
    assert db.session.get(Account, "u-temp").status == "DISABLED"


def test_temp_staff_unused_for_30_days_is_disabled(app):
    add("u-temp", "temp@evp.test", contract_end=date.today() + timedelta(days=60),
        last_login=r08.now() - timedelta(days=31))
    add("u-temp2", "temp2@evp.test", contract_end=date.today() + timedelta(days=60),
        last_login=r08.now() - timedelta(days=5))
    assert r08.disable_expired_staff() == ["temp@evp.test"]
    assert db.session.get(Account, "u-temp2").status == "ACTIVE"


def test_permanent_staff_are_not_disabled_for_being_unused(app):
    db.session.get(Account, "u-officer").last_login = r08.now() - timedelta(days=90)
    db.session.commit()
    assert r08.disable_expired_staff() == []


def test_disable_command(app):
    add("u-temp", "temp@evp.test", contract_end=date.today() - timedelta(days=1))
    out = app.test_cli_runner().invoke(args=["auth", "disable-expired-staff"])
    assert "disabled temp@evp.test" in out.output


# ------------------------------------------------------------------ seed passwords
def test_seed_command_sets_real_hashes(app, monkeypatch):
    runner = app.test_cli_runner()
    monkeypatch.delenv("DEV_SEED_PASSWORD", raising=False)
    assert runner.invoke(args=["auth", "seed-dev-passwords"]).exit_code != 0
    monkeypatch.setenv("DEV_SEED_PASSWORD", "a-new-dev-password")
    assert runner.invoke(args=["auth", "seed-dev-passwords"]).exit_code == 0
    acc = db.session.get(Account, "u-officer")
    assert acc.password_hash.startswith("$argon2id$") and "a-new-dev-password" not in acc.password_hash
    assert sign_in(app.test_client(), password="a-new-dev-password").status_code == 200


# ------------------------------------------------------------------ input
def test_login_input_is_validated(client):
    assert client.post("/auth/login", json={"email": "not-an-email", "password": "x"}).status_code == 400
    assert client.post("/auth/login", json={"email": "a@b.c", "password": "x", "extra": 1}).status_code == 400
