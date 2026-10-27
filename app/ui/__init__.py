"""The graphical front end (GUI).

Server-rendered pages (Jinja, auto-escaped) for every role. The pages hold no business logic of their own:
every action calls the same REST API the rest of the app exposes (/auth, /enrolment, /ballot, /election,
/audit), so every security check (validation, CSRF, sign-in, roles, MFA, R14 access) applies to the GUI too.
"""
from flask import Blueprint

bp = Blueprint("ui", __name__)

from . import routes  # noqa: E402,F401
