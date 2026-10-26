"""R8 - Access security.

How it works (one sentence each):
  1. POST /auth/login checks the password (Argon2 hash) and starts a NEW session; the second step (R12) comes next.
  2. The session cookie is HttpOnly, Secure and SameSite=Strict, so scripts and other websites cannot use it
     (set in app/common/auth.py).
  3. A session with no request for 5 minutes is signed out (app/common/auth.py), for shared terminals.
  4. Temporary staff (accounts with a contract end date) are disabled when the contract ends or after
     30 days without signing in. This is checked at every sign-in and by `flask disable-expired-staff`.
  5. POST /auth/logout ends the session.
  6. `flask seed-dev-passwords` gives the seed accounts a real password for local testing.
"""
import os
from datetime import timedelta

import click
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from flask import jsonify, request, session

from . import bp
from .models import Account
from .r14_models import now
from app.common.audit import audit
from app.common.auth import start_session
from app.common.validate import validate
from app.extensions import db

UNUSED_DAYS = 30
SEED_DOMAIN = "@evp.test"
WRONG = "Email or password is wrong."             # the same message whether or not the email exists

_hasher = PasswordHasher()
_DUMMY_HASH = _hasher.hash("not-a-real-password")  # used when the email is unknown, so timing gives nothing away

LOGIN_SCHEMA = {
    "email":    {"type": str, "max_length": 255, "pattern": r"[^@\s]+@[^@\s]+\.[^@\s]+", "required": True},
    "password": {"type": str, "min_length": 1, "max_length": 256, "strip": False, "allow_markup": True,
                 "required": True},
}


class LoginError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _password_ok(stored_hash, password):
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def temp_staff_expired(acc, at=None):
    """True if this is a temporary staff account whose contract ended or that was unused for 30 days."""
    if acc.contract_end is None or acc.role == "voter":
        return False
    at = at or now()
    if acc.contract_end < at.date():
        return True
    last_used = acc.last_login or acc.created_at
    return last_used is not None and at - last_used > timedelta(days=UNUSED_DAYS)


def disable_expired_staff():
    """Disable every temporary staff account that has expired. Returns the emails that were disabled."""
    disabled = []
    for acc in Account.query.filter(Account.contract_end.isnot(None), Account.status == "ACTIVE").all():
        if temp_staff_expired(acc):
            acc.status = "DISABLED"
            disabled.append(acc.email)
            audit("AUTH_ACCOUNT_DISABLED", actor_id="system", details={"account_id": acc.id, "reason": "temp_staff_expired"})
    db.session.commit()
    return sorted(disabled)


def login(email, password):
    acc = Account.query.filter_by(email=email.lower()).first()
    if acc is None:
        _password_ok(_DUMMY_HASH, password)
        audit("AUTH_LOGIN_FAILED", actor_id="anonymous", details={"reason": "unknown_email"})
        raise LoginError("LOGIN_FAILED", WRONG, 401)
    if not _password_ok(acc.password_hash, password):
        audit("AUTH_LOGIN_FAILED", actor_id=acc.id, details={"reason": "wrong_password"})
        raise LoginError("LOGIN_FAILED", WRONG, 401)
    if acc.status == "ACTIVE" and temp_staff_expired(acc):
        acc.status = "DISABLED"
        db.session.commit()
        audit("AUTH_ACCOUNT_DISABLED", actor_id="system", details={"account_id": acc.id, "reason": "temp_staff_expired"})
    if acc.status != "ACTIVE":
        audit("AUTH_LOGIN_REFUSED", actor_id=acc.id, details={"status": acc.status})
        raise LoginError("ACCOUNT_DISABLED", "This account cannot sign in. Contact the AEC.", 403)

    acc.last_login = now()
    db.session.commit()
    start_session(acc.id)
    audit("AUTH_LOGIN_PASSWORD_OK", actor_id=acc.id, details={})
    if acc.mfa_secret_enc:
        next_step = "app"
    elif acc.role == "voter":
        next_step = "email"
    else:
        next_step = "setup"                         # staff must set up the app before going further
    return {"status": "MFA_REQUIRED", "next": next_step}


# ----------------------------------------------------------------- routes
@bp.post("/login")                                # final URL: /auth/login
def login_route():
    data = validate(LOGIN_SCHEMA, request.get_json(silent=True) or {})
    try:
        return jsonify(login(data["email"], data["password"]))
    except LoginError as e:
        return jsonify({"error": e.code, "message": e.message}), e.status


@bp.post("/logout")
def logout_route():
    user_id = session.get("user_id")
    session.clear()
    if user_id:
        audit("AUTH_LOGOUT", actor_id=user_id, details={})
    return jsonify({"status": "SIGNED_OUT"})


# ----------------------------------------------------------------- commands
@bp.cli.command("disable-expired-staff", help="R8: disable temporary staff past their contract or unused for 30 days.")
def disable_expired_staff_command():
    for email in disable_expired_staff():
        click.echo(f"disabled {email}")


@bp.cli.command("seed-dev-passwords", help="Local testing only: set every @evp.test account's password.")
def seed_dev_passwords_command():
    password = os.environ.get("DEV_SEED_PASSWORD", "")
    if len(password) < 12:
        raise click.ClickException("Set DEV_SEED_PASSWORD (12+ characters) in .env first.")
    accounts = Account.query.filter(Account.email.like(f"%{SEED_DOMAIN}")).all()
    for acc in accounts:
        acc.password_hash = _hasher.hash(password)
    db.session.commit()
    click.echo(f"set the password for {len(accounts)} seed accounts")
