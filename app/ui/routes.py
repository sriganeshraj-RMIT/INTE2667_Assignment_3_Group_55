"""GUI pages. Reading is done here (server side, parameterised queries); every change goes through the REST API
from the browser (static/js/api.js), so the same checks protect the API and the GUI.

Security notes for the front end:
  * all output is auto-escaped by Jinja; no page uses |safe;
  * no inline JavaScript or inline styles: everything is in /static, which the Content-Security-Policy allows;
  * every change is a fetch() with the X-CSRF-Token header (R18);
  * pages check sign-in, MFA and role on the SERVER before rendering; the API checks again on every action;
  * the voter's ballot is sealed and the voting pass is blinded IN THE BROWSER (static/js/evp-crypto.js), and
    the ballot is cast without the sign-in cookie (R1, R5).
"""
from functools import wraps

from flask import redirect, render_template, request, url_for
from sqlalchemy import text

from . import bp
from app.auth.models import Account
from app.common.auth import signed_in_user
from app.extensions import db

STAFF_ROLES = ("officer", "delegate", "counting_officer", "auditor", "custodian", "admin")


# ------------------------------------------------------------------ helpers
def page(*roles, allow_pending_mfa=False):
    """Page guard: not signed in -> the sign-in page; wrong role -> a 403 page. The API still checks every action."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = signed_in_user(allow_pending_mfa=allow_pending_mfa)
            if user is None:
                return redirect(url_for("ui.login", next=request.path))
            if roles and user["role"] not in roles:
                return render_template("ui/forbidden.html"), 403
            return view(user, *args, **kwargs)
        return wrapper
    return decorator


def _safe_next(target):
    """Only allow redirects to our own pages (no open redirect)."""
    return target if isinstance(target, str) and target.startswith("/") and not target.startswith("//") else None


def elections(division=None):
    sql = "SELECT id, name, division, state, opens_at, closes_at, status FROM elections"
    params = {}
    if division:
        sql += " WHERE division = :d"
        params["d"] = division
    return db.session.execute(text(sql + " ORDER BY opens_at, id"), params).mappings().all()


def candidates(election_id):
    return db.session.execute(text("SELECT id, name, party, ballot_pos FROM candidates WHERE election_id = :e "
                                   "ORDER BY ballot_pos, id"), {"e": election_id}).mappings().all()


def _refresh_status():
    """Keep DRAFT/APPROVED/OPEN/CLOSED in line with the locked times (R10) before showing it."""
    from app.election.r10_lock import refresh_status
    try:
        refresh_status()
    except Exception:                            # a page must still render if the clock update fails
        db.session.rollback()


@bp.app_context_processor
def _who_is_signed_in():
    user = signed_in_user()
    email = None
    if user:
        acc = db.session.get(Account, user["id"])
        email = acc.email if acc else None
    return {"me": user, "me_email": email}


# ------------------------------------------------------------------ public
@bp.get("/")
def home():
    return render_template("ui/home.html")


@bp.get("/elections")
def election_list():
    _refresh_status()
    return render_template("ui/elections.html", elections=elections())


@bp.get("/elections/<election_id>")
def election_detail(election_id):
    from app.ballot.r20_models import BallotChainHead
    from app.election.r10_lock import ElectionError, check_definition
    from app.election.r13_results import ResultError, published_result
    _refresh_status()
    election = next((e for e in elections() if e["id"] == election_id), None)
    if election is None:
        return render_template("ui/not_found.html"), 404
    try:
        definition = check_definition(election_id)
    except ElectionError:
        definition = {"locked": False}
    try:
        result = published_result(election_id)
    except ResultError:
        result = None
    head = db.session.get(BallotChainHead, election_id)
    return render_template("ui/election_detail.html", election=election, definition=definition,
                           result=result, head=head, candidates=candidates(election_id))


@bp.get("/receipt")
def receipt():
    return render_template("ui/receipt.html", elections=elections())


@bp.get("/enrol")
def enrol():
    return render_template("ui/enrol.html")


# ------------------------------------------------------------------ sign-in
@bp.get("/login")
def login():
    return render_template("ui/login.html", next=_safe_next(request.args.get("next")) or "")


@bp.get("/mfa")
@page(allow_pending_mfa=True)
def mfa(user):
    acc = db.session.get(Account, user["id"])
    if acc.mfa_secret_enc:
        step = "app"
    elif acc.role == "voter":
        step = "email"
    else:
        step = "setup"
    return render_template("ui/mfa.html", step=step, role=acc.role,
                           next=_safe_next(request.args.get("next")) or url_for("ui.dashboard"))


@bp.get("/dashboard")
@page()
def dashboard(user):
    return render_template("ui/dashboard.html")


# ------------------------------------------------------------------ voter
@bp.get("/vote")
@page("voter")
def vote_list(user):
    _refresh_status()
    from app.ballot.r03_register import has_voted
    rows = [dict(e, voted=has_voted(user["id"], e["id"])) for e in elections(user["division"])] \
        if user.get("division") else []
    return render_template("ui/vote_list.html", elections=rows)


@bp.get("/vote/<election_id>")
@page("voter")
def vote(user, election_id):
    from app.ballot.r03_register import has_voted
    from app.election.r10_lock import ElectionError, check_definition
    _refresh_status()
    election = next((e for e in elections(user.get("division")) if e["id"] == election_id), None)
    if election is None:
        return render_template("ui/not_found.html"), 404
    try:
        definition = check_definition(election_id)
    except ElectionError:
        definition = {"locked": False, "valid": False}
    return render_template("ui/vote.html", election=election, definition=definition,
                           voted=has_voted(user["id"], election_id))


@bp.get("/account/address")
@page("voter")
def address_change(user):
    return render_template("ui/address.html")


# ------------------------------------------------------------------ staff
@bp.get("/staff/elections")
@page("delegate", "custodian", "counting_officer", "admin")
def staff_elections(user):
    from app.auth.r14_elevation import has_active_grant
    from app.ballot.r05_models import ElectionKey
    _refresh_status()
    rows = []
    for e in elections():
        rows.append(dict(e, has_key=db.session.get(ElectionKey, e["id"]) is not None,
                         candidates=candidates(e["id"])))
    access = {s: has_active_grant(user["id"], s) for s in ("counting", "results")} \
        if user["role"] in ("counting_officer", "admin") else {}
    return render_template("ui/staff_elections.html", elections=rows, access=access)


@bp.get("/staff/access")
@page("counting_officer", "admin", "custodian")
def staff_access(user):
    from app.auth.r14_models import AccessGrant, now
    mine = AccessGrant.query.filter_by(requester_id=user["id"]).order_by(AccessGrant.requested_at.desc()).limit(20).all()
    pending = []
    if user["role"] in ("admin", "custodian"):
        pending = AccessGrant.query.filter_by(status="PENDING").order_by(AccessGrant.requested_at).all()
    return render_template("ui/staff_access.html", mine=mine, pending=pending, now=now())


@bp.get("/staff/exclusions")
@page("delegate")
def staff_exclusions(user):
    from app.election.r19_models import Exclusion
    rows = Exclusion.query.order_by(Exclusion.proposed_at.desc()).limit(50).all()
    names = {c["id"]: c["name"] for e in elections() for c in candidates(e["id"])}
    return render_template("ui/staff_exclusions.html", exclusions=rows, names=names,
                           elections=[dict(e, candidates=candidates(e["id"])) for e in elections()])


@bp.get("/staff/officer")
@page("officer")
def staff_officer(user):
    _refresh_status()
    return render_template("ui/staff_officer.html", elections=elections(user.get("division")))


@bp.get("/audit")
@page("auditor", "admin")
def audit_page(user):
    _refresh_status()
    return render_template("ui/audit.html", elections=elections())


# ------------------------------------------------------------------ demo data (command line only, never a web route)
@bp.cli.command("demo-election", help="Local demo only: add a DRAFT election in Melbourne that opens soon.")
def demo_election_command():
    import uuid
    from datetime import timedelta

    import click
    from app.auth.r14_models import now

    opens = click.prompt("Polls open in how many minutes", default=10, type=int)
    length = click.prompt("Polls stay open for how many minutes", default=10, type=int)
    election_id = str(uuid.uuid4())
    start = now().replace(microsecond=0) + timedelta(minutes=opens)
    db.session.execute(text("INSERT INTO elections (id, name, division, state, opens_at, closes_at, status) "
                            "VALUES (:id, :name, 'Melbourne', 'VIC', :o, :c, 'DRAFT')"),
                       {"id": election_id, "name": f"Demo election {start:%H:%M} UTC", "o": str(start),
                        "c": str(start + timedelta(minutes=length))})
    for pos, (name, party) in enumerate((("Alice Smith", "Party A"), ("Bob Jones", "Party B"),
                                         ("Carol White", "Party C")), 1):
        db.session.execute(text("INSERT INTO candidates (id, election_id, name, party, ballot_pos) "
                                "VALUES (:id, :e, :n, :p, :pos)"),
                           {"id": str(uuid.uuid4()), "e": election_id, "n": name, "p": party, "pos": pos})
    db.session.commit()
    click.echo(f"Added {election_id}: opens {start} UTC for {length} minutes. Lock it before it opens.")
