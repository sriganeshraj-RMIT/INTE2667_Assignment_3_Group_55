"""Sign-in checks shared by every blueprint.

R8  - who is signed in: the session cookie (HttpOnly, Secure, SameSite=Strict), 5 minutes idle timeout,
      login_required, role_required and current_user().
R12 - mfa_required: the second sign-in step was passed in the last 15 minutes.

Someone is only fully signed in after BOTH steps: the password (POST /auth/login) and the second step
(POST /auth/mfa/verify). In between, only the MFA routes accept them (password_step_required).

Like CSRF, these checks are off while app.config["TESTING"] is True, so tests that act as a user by
replacing current_user keep working. To test the real checks set LOGIN_ENFORCE / MFA_ENFORCE = True.
"""
import time
from functools import wraps

from flask import current_app, request, session
from werkzeug.exceptions import Forbidden, Unauthorized

IDLE_SECONDS = 5 * 60             # R8: sign out after 5 minutes without a request (shared terminals)
MFA_FRESH_SECONDS = 15 * 60       # R12: how long a passed second step counts as "fresh"


class NotSignedIn(Unauthorized):
    error_code = "NOT_SIGNED_IN"
    description = "Please sign in."


class WrongRole(Forbidden):
    error_code = "FORBIDDEN"
    description = "Your account cannot do this."


class MfaRequired(Unauthorized):
    error_code = "MFA_REQUIRED"
    description = "Confirm the code from your authenticator app (or email) first."


def _enforced(flag):
    value = current_app.config.get(flag)
    return (not current_app.config.get("TESTING", False)) if value is None else bool(value)


def _log_refusal(event, actor_id, details):
    from app.common.audit import audit               # imported here to avoid a circular import
    audit(event, actor_id=actor_id, details=details)


# ------------------------------------------------------------------ session (R8)
def init_auth(app):
    """Called from create_app: cookie protection and the idle timeout."""
    app.config["SESSION_COOKIE_HTTPONLY"] = True       # scripts cannot read the cookie
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"   # other websites cannot send it
    app.config["SESSION_COOKIE_SECURE"] = True         # only sent over HTTPS (browsers also allow localhost)

    @app.before_request
    def _idle_timeout():
        if "user_id" not in session:
            return
        last = session.get("last_seen")
        limit = current_app.config.get("IDLE_SECONDS", IDLE_SECONDS)
        if not isinstance(last, int) or time.time() - last > limit:
            session.clear()                                      # left open too long: signed out
        else:
            session["last_seen"] = int(time.time())


def start_session(account_id):
    """After a correct password: throw away the old session (no fixation) and start a fresh one."""
    session.clear()
    session["user_id"] = account_id
    session["last_seen"] = int(time.time())


def signed_in_user(allow_pending_mfa=False):
    """{id, role, division, state} for the person in this session, or None.

    Without allow_pending_mfa the person must also have passed the second step (R12).
    The account is re-read every time, so a disabled account stops working straight away.
    """
    from app.auth.models import Account                          # imported here to avoid a circular import
    from app.extensions import db

    account_id = session.get("user_id")
    if not account_id:
        return None
    if not allow_pending_mfa and session.get("mfa_user") != account_id:
        return None
    acc = db.session.get(Account, account_id)
    if acc is None or acc.status != "ACTIVE":
        session.clear()
        return None
    return {"id": acc.id, "role": acc.role, "division": acc.division, "state": acc.state}


def current_user():
    """Returns {id, role, division, state} for the fully signed-in user, or None."""
    return signed_in_user()


def login_required(f):
    """Decorator: refuses unless both sign-in steps are done. R8."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _enforced("LOGIN_ENFORCE") and signed_in_user() is None:
            raise NotSignedIn()
        return f(*args, **kwargs)
    return decorated


def password_step_required(f):
    """Decorator for the MFA routes only: the password step is enough. R8 + R12."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _enforced("LOGIN_ENFORCE") and signed_in_user(allow_pending_mfa=True) is None:
            raise NotSignedIn()
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Decorator: refuses when the signed-in user's role is not one of roles. R8."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if _enforced("LOGIN_ENFORCE"):
                user = signed_in_user()
                if user is None:
                    raise NotSignedIn()
                if user["role"] not in roles:
                    # Logged here once for every route, so R11 can see wrong-role attempts.
                    # Only the role and the path: never the request body (it can hold key shares).
                    _log_refusal("AUTH_ACCESS_DENIED", user["id"], {"role": user["role"], "path": request.path})
                    raise WrongRole()
            return f(*args, **kwargs)
        return decorated
    return decorator


# ------------------------------------------------------------------ second step (R12)
def mfa_passed_recently():
    """True if this session passed the second sign-in step (R12) in the last MFA_FRESH_SECONDS."""
    at, who = session.get("mfa_at"), session.get("mfa_user")
    if not who or not isinstance(at, int):
        return False
    if session.get("user_id") and session["user_id"] != who:   # the step must be the same person's
        return False
    return 0 <= time.time() - at <= current_app.config.get("MFA_FRESH_SECONDS", MFA_FRESH_SECONDS)


def mfa_required(f):
    """Decorator: requires a fresh second-factor check in this session. R12."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if _enforced("MFA_ENFORCE") and not mfa_passed_recently():
            raise MfaRequired()
        return f(*args, **kwargs)
    return decorated
