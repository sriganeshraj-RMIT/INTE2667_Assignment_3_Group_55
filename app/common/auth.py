import time
from functools import wraps

from flask import current_app, jsonify, session
from werkzeug.exceptions import Unauthorized

MFA_FRESH_SECONDS = 15 * 60      # R12: how long a passed second step counts as "fresh"


class MfaRequired(Unauthorized):
    error_code = "MFA_REQUIRED"
    description = "Confirm the code from your authenticator app (or email) first."


def mfa_passed_recently():
    """True if this session passed the second sign-in step (R12) in the last MFA_FRESH_SECONDS."""
    at, who = session.get("mfa_at"), session.get("mfa_user")
    if not who or not isinstance(at, int):
        return False
    if session.get("user_id") and session["user_id"] != who:   # R8 sets user_id; the step must be the same person's
        return False
    return 0 <= time.time() - at <= current_app.config.get("MFA_FRESH_SECONDS", MFA_FRESH_SECONDS)

def login_required(f):
    """Decorator: rejects requests with no valid session. R8, R20."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # TODO R8: check JWT or session cookie
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    """Decorator: rejects requests where the caller's role is not in roles. R20."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # TODO R20: check current_user().role against roles
            return f(*args, **kwargs)
        return decorated
    return decorator

def mfa_required(f):
    """Decorator: requires a fresh second-factor check in this session. R12.

    Like CSRF, it is off while app.config["TESTING"] is True so other people's tests keep working.
    To test it set app.config["MFA_ENFORCE"] = True.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        enforce = current_app.config.get("MFA_ENFORCE")
        if enforce is None:
            enforce = not current_app.config.get("TESTING", False)
        if enforce and not mfa_passed_recently():
            raise MfaRequired()
        return f(*args, **kwargs)
    return decorated

def current_user():
    """Returns {id, role, division, state} for the signed-in user, or None."""
    # TODO R8: decode from JWT or session
    return None