"""Tables in identity_db that belong to sign-in (R8 and R12).

`Account` maps the existing `accounts` table from db/init/01_identity.sql. R8 (password sign-in) uses the
same class, so add new columns here rather than making a second model for the same table.
"""
from app.extensions import db


class Account(db.Model):
    __tablename__ = "accounts"

    id = db.Column(db.String(36), primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    division = db.Column(db.String(100))
    state = db.Column(db.String(50))
    status = db.Column(db.String(10), nullable=False, default="PENDING")
    contract_end = db.Column(db.Date)
    last_login = db.Column(db.DateTime)
    # R12 - second sign-in step
    mfa_secret_enc = db.Column(db.String(512))      # authenticator secret, encrypted, never stored in plain text
    mfa_last_step = db.Column(db.BigInteger)         # last accepted 30-second code window, so a code works once
    mfa_failed = db.Column(db.Integer, nullable=False, default=0)
    mfa_locked_until = db.Column(db.DateTime)


class MfaEmailCode(db.Model):
    """R12 - one pending emailed code per voter. Only a keyed hash of the code is stored."""
    __tablename__ = "mfa_email_codes"

    account_id = db.Column(db.String(36), primary_key=True)
    code_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
