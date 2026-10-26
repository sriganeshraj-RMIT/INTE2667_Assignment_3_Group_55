"""R12 - second sign-in step for everyone.

How it works (one sentence each):
  1. Staff set up an authenticator app once (POST /auth/mfa/setup). The secret is stored encrypted.
  2. After the password step (R8), everyone confirms a 6-digit code (POST /auth/mfa/verify).
     Staff must use the app; there is no fallback for staff.
  3. Voters without the app can ask for a one-time code by email instead (POST /auth/mfa/email-code).
  4. A code works once, emailed codes expire after 5 minutes, and 5 wrong codes lock the step for 15 minutes.
  5. @mfa_required (app/common/auth.py) then refuses sensitive actions unless the step was passed recently.
  6. Before each election an admin runs GET /auth/mfa/readiness to list staff who have not set up the app
     (the issue asks for this check at least 14 days before the election).
"""
import base64
import hashlib
import hmac
import os
import secrets
import smtplib
import time
from datetime import timedelta
from email.message import EmailMessage

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from flask import current_app, jsonify, request, session

from . import bp
from .models import Account, MfaEmailCode
from .r14_models import now
from app.common.audit import audit
from app.common.auth import login_required, mfa_required, password_step_required, signed_in_user
from app.common.validate import validate
from app.extensions import db

ISSUER = "EVP (AEC)"
MAX_FAILURES = 5
LOCK_MINUTES = 15
EMAIL_CODE_MINUTES = 5
EMAIL_CODE_ATTEMPTS = 5

VERIFY_SCHEMA = {"code": {"type": str, "pattern": r"\d{6}", "required": True}}


class MfaError(Exception):
    """A refusal that is turned into the team's error JSON: {"error": CODE, "message": text}."""

    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


def current_user():
    """The person who passed the password step (R8). The second step is what these routes are for."""
    return signed_in_user(allow_pending_mfa=True)


def _timestamp():
    """Seconds since 1970. A function so the tests can move the clock."""
    return time.time()


def _fernet():
    key = hashlib.sha256(b"r12-mfa-secret:" + current_app.config["SECRET_KEY"].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def _code_hash(account_id, code):
    key = current_app.config["SECRET_KEY"].encode()
    return hmac.new(key, f"{account_id}:{code}".encode(), hashlib.sha256).hexdigest()


def _account(user):
    acc = db.session.get(Account, user["id"]) if user else None
    if acc is None:
        raise MfaError("NOT_SIGNED_IN", "Sign in with your password first.", 401)
    return acc


def _send_email(to, code):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "no-reply@evp.test", to, "Your EVP sign-in code"
    msg.set_content(f"Your sign-in code is {code}. It expires in {EMAIL_CODE_MINUTES} minutes. "
                    "If you did not try to sign in, ignore this email.")
    host, port = os.environ.get("MAIL_HOST", "localhost"), int(os.environ.get("MAIL_PORT", "1025"))
    with smtplib.SMTP(host, port, timeout=5) as smtp:
        smtp.send_message(msg)


# ------------------------------------------------------------------ logic
def setup_totp(user):
    acc = _account(user)
    if acc.mfa_secret_enc:
        raise MfaError("MFA_ALREADY_SET_UP", "An authenticator app is already set up for this account.", 409)
    secret = pyotp.random_base32()
    acc.mfa_secret_enc = _fernet().encrypt(secret.encode()).decode()
    db.session.commit()
    audit("AUTH_MFA_SETUP", actor_id=acc.id, details={})
    return secret, pyotp.TOTP(secret).provisioning_uri(name=acc.email, issuer_name=ISSUER)


def _totp_ok(acc, code):
    try:
        secret = _fernet().decrypt(acc.mfa_secret_enc.encode()).decode()
    except InvalidToken:
        return False
    totp, step_now = pyotp.TOTP(secret), int(_timestamp() // 30)
    for step in (step_now - 1, step_now, step_now + 1):          # allow 30 seconds of clock drift
        if hmac.compare_digest(totp.at(step * 30), code):
            if acc.mfa_last_step is not None and step <= acc.mfa_last_step:
                return False                                     # this code was already used
            acc.mfa_last_step = step
            return True
    return False


def _email_code_ok(acc, code):
    row = db.session.get(MfaEmailCode, acc.id)
    if row is None:
        return False
    if row.expires_at < now() or row.attempts >= EMAIL_CODE_ATTEMPTS:
        db.session.delete(row)
        return False
    if hmac.compare_digest(row.code_hash, _code_hash(acc.id, code)):
        db.session.delete(row)                                   # one use only
        return True
    row.attempts += 1
    return False


def verify_code(user, code):
    acc = _account(user)
    if acc.mfa_locked_until and acc.mfa_locked_until > now():
        raise MfaError("MFA_LOCKED", "Too many wrong codes. Try again later.", 429)
    if not acc.mfa_secret_enc and acc.role != "voter":
        raise MfaError("MFA_NOT_SET_UP", "Staff must set up an authenticator app first.", 403)

    ok = bool(acc.mfa_secret_enc) and _totp_ok(acc, code)
    if not ok and acc.role == "voter":                           # emailed code: voters only
        ok = _email_code_ok(acc, code)

    if not ok:
        acc.mfa_failed = (acc.mfa_failed or 0) + 1
        locked = acc.mfa_failed >= MAX_FAILURES
        if locked:
            acc.mfa_locked_until, acc.mfa_failed = now() + timedelta(minutes=LOCK_MINUTES), 0
        db.session.commit()
        audit("AUTH_MFA_LOCKED" if locked else "AUTH_MFA_FAILED", actor_id=acc.id, details={})
        raise MfaError("MFA_WRONG_CODE", "That code is not correct.", 401)

    acc.mfa_failed, acc.mfa_locked_until = 0, None
    db.session.commit()
    session["mfa_user"], session["mfa_at"] = acc.id, int(_timestamp())
    audit("AUTH_MFA_PASSED", actor_id=acc.id, details={})


def send_email_code(user):
    acc = _account(user)
    if acc.role != "voter":
        raise MfaError("EMAIL_CODE_NOT_ALLOWED", "Staff must use their authenticator app.", 403)
    code = f"{secrets.randbelow(10 ** 6):06d}"
    row = db.session.get(MfaEmailCode, acc.id) or MfaEmailCode(account_id=acc.id)
    row.code_hash, row.attempts = _code_hash(acc.id, code), 0
    row.expires_at = now() + timedelta(minutes=EMAIL_CODE_MINUTES)
    db.session.add(row)
    db.session.commit()
    _send_email(acc.email, code)
    audit("AUTH_MFA_EMAIL_SENT", actor_id=acc.id, details={})


def staff_without_mfa():
    rows = Account.query.filter(Account.role != "voter", Account.status == "ACTIVE").all()
    return sorted(a.email for a in rows if not a.mfa_secret_enc)


# ----------------------------------------------------------------- routes
@bp.post("/mfa/setup")                            # final URL: /auth/mfa/setup
@password_step_required
def mfa_setup():
    try:
        secret, uri = setup_totp(current_user())
    except MfaError as e:
        return error_response(e)
    return jsonify({"secret": secret, "otpauth_uri": uri}), 201


@bp.post("/mfa/verify")
@password_step_required
def mfa_verify():
    data = validate(VERIFY_SCHEMA, request.get_json(silent=True) or {})
    try:
        verify_code(current_user(), data["code"])
    except MfaError as e:
        return error_response(e)
    return jsonify({"status": "MFA_PASSED"})


@bp.post("/mfa/email-code")
@password_step_required
def mfa_email_code():
    try:
        send_email_code(current_user())
    except MfaError as e:
        return error_response(e)
    return jsonify({"status": "SENT"})


@bp.get("/mfa/readiness")
@login_required
@mfa_required
def mfa_readiness():
    user = current_user()
    if not user or user.get("role") != "admin":
        return error_response(MfaError("FORBIDDEN", "Only an admin can run this check.", 403))
    missing = staff_without_mfa()
    return jsonify({"ready": not missing, "staff_without_mfa": missing})
