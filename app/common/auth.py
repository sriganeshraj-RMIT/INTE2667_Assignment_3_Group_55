from functools import wraps
from flask import jsonify

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
    """Decorator: requires a fresh second-factor check in this session. R12."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # TODO R12: check MFA timestamp in session
        return f(*args, **kwargs)
    return decorated

def current_user():
    """Returns {id, role, division, state} for the signed-in user, or None."""
    # TODO R8: decode from JWT or session
    return None