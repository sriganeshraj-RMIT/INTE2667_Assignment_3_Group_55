"""GUI - every page renders for the right people only, and the front end keeps the security rules:
no inline scripts or styles (CSP), escaped output (XSS), no open redirect, sign-in and role checks on the server."""
import re
import time

import pytest
from sqlalchemy import text

from app import create_app
from app.auth.models import Account
from app.extensions import db

ROLES = ("voter", "officer", "delegate", "counting_officer", "auditor", "custodian", "admin")
PUBLIC = ("/", "/elections", "/elections/e1", "/receipt", "/enrol", "/login")
PAGES = {                       # page -> roles allowed to open it
    "/dashboard": ROLES,
    "/vote": ("voter",),
    "/vote/e1": ("voter",),
    "/account/address": ("voter",),
    "/staff/elections": ("delegate", "custodian", "counting_officer", "admin"),
    "/staff/access": ("counting_officer", "admin", "custodian"),
    "/staff/exclusions": ("delegate",),
    "/staff/officer": ("officer",),
    "/audit": ("auditor", "admin"),
}


@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True)
    with app.app_context():
        db.create_all()
        db.session.execute(text("""CREATE TABLE elections (id TEXT PRIMARY KEY, name TEXT, division TEXT, state TEXT,
            opens_at DATETIME, closes_at DATETIME, definition_fp TEXT, definition_sig TEXT, status TEXT)"""))
        db.session.execute(text("CREATE TABLE candidates (id TEXT PRIMARY KEY, election_id TEXT, name TEXT, party TEXT, ballot_pos INTEGER)"))
        db.session.execute(text("INSERT INTO elections VALUES ('e1', 'Test <script>alert(1)</script>', 'Melbourne', 'VIC', "
                                "'2026-11-01 08:00:00', '2026-11-01 18:00:00', NULL, NULL, 'DRAFT')"))
        db.session.execute(text("INSERT INTO candidates VALUES ('c1', 'e1', 'Alice <b>Smith</b>', 'Party A', 1), "
                                "('c2', 'e1', 'Bob', 'Party B', 2)"))
        for role in ROLES:
            db.session.add(Account(id=f"u-{role}", email=f"{role}@evp.test", password_hash="x", role=role,
                                   division="Melbourne", state="VIC", status="ACTIVE"))
        db.session.commit()
        yield app
        db.session.remove()


def signed_in(app, role, mfa=True):
    client = app.test_client()
    with client.session_transaction() as s:
        now = int(time.time())
        s.update(user_id=f"u-{role}", last_seen=now)
        if mfa:
            s.update(mfa_user=f"u-{role}", mfa_at=now)
    return client


def check_front_end_rules(resp):
    html = resp.get_data(as_text=True)
    assert "Content-Security-Policy" in resp.headers
    csp = resp.headers["Content-Security-Policy"]
    assert "unsafe-inline" not in csp and "http" not in csp.split("script-src")[1].split(";")[0]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    for tag in re.findall(r"<script\b[^>]*>", html):
        assert 'src="/static/' in tag and f'nonce="{nonce}"' in tag, f"inline or third-party script: {tag}"
    assert not re.search(r"\sstyle=", html), "inline style attribute (blocked by the CSP)"
    assert not re.search(r"\son[a-z]+=", html), "inline event handler (blocked by the CSP)"
    assert '<meta name="csrf-token"' in html


# ------------------------------------------------------------------ public pages
@pytest.mark.parametrize("path", PUBLIC)
def test_public_pages_render_and_follow_the_front_end_rules(app, path):
    resp = app.test_client().get(path)
    assert resp.status_code == 200
    check_front_end_rules(resp)


def test_data_from_the_database_is_escaped(app):
    html = app.test_client().get("/elections").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    detail = app.test_client().get("/elections/e1").get_data(as_text=True)
    assert "<b>Smith</b>" not in detail and "&lt;b&gt;Smith&lt;/b&gt;" in detail


def test_unknown_election_is_404(app):
    assert app.test_client().get("/elections/nope").status_code == 404


@pytest.mark.parametrize("target, expected", [("/vote", "/vote"), ("//evil.example", ""), ("https://evil.example", "")])
def test_login_never_redirects_off_site(app, target, expected):
    html = app.test_client().get(f"/login?next={target}").get_data(as_text=True)
    assert f'data-next="{expected}"' in html


# ------------------------------------------------------------------ signed-in pages
@pytest.mark.parametrize("path", sorted(PAGES))
def test_signed_out_users_are_sent_to_sign_in(app, path):
    resp = app.test_client().get(path)
    assert resp.status_code == 302 and resp.headers["Location"].startswith("/login?next=")


@pytest.mark.parametrize("path", sorted(PAGES))
def test_a_password_alone_does_not_open_staff_or_voter_pages(app, path):
    resp = signed_in(app, PAGES[path][0], mfa=False).get(path)
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


@pytest.mark.parametrize("path, role", [(p, r) for p in sorted(PAGES) for r in ROLES])
def test_each_page_opens_only_for_its_roles(app, path, role):
    resp = signed_in(app, role).get(path)
    if role in PAGES[path]:
        assert resp.status_code in (200, 404)          # 404 only for /vote/e1 when the voter's division has no such election
        if resp.status_code == 200:
            check_front_end_rules(resp)
    else:
        assert resp.status_code == 403


def test_mfa_page_needs_the_password_step(app):
    assert app.test_client().get("/mfa").status_code == 302
    staff = signed_in(app, "delegate", mfa=False).get("/mfa").get_data(as_text=True)
    voter = signed_in(app, "voter", mfa=False).get("/mfa").get_data(as_text=True)
    assert 'data-step="setup"' in staff and "email-btn" not in staff          # no email fallback for staff (R12)
    assert 'data-step="email"' in voter and "email-btn" in voter


def test_navigation_shows_only_the_users_own_tools(app):
    officer = signed_in(app, "officer").get("/dashboard").get_data(as_text=True)
    assert 'href="/staff/officer"' in officer and 'href="/audit"' not in officer
    auditor = signed_in(app, "auditor").get("/dashboard").get_data(as_text=True)
    assert 'href="/audit"' in auditor and 'href="/staff/officer"' not in auditor


def test_vote_page_offers_a_ballot_only_while_polls_are_open_and_the_ballot_is_signed(app):
    voter = signed_in(app, "voter")
    assert "ballot-form" not in voter.get("/vote/e1").get_data(as_text=True)          # DRAFT: no ballot
    db.session.execute(text("UPDATE elections SET status = 'OPEN', definition_fp = 'x', definition_sig = 'y', "
                            "opens_at = '2000-01-01 00:00:00', closes_at = '2999-01-01 00:00:00' WHERE id = 'e1'"))
    db.session.commit()
    html = voter.get("/vote/e1").get_data(as_text=True)
    assert "ballot-form" not in html and "does not match its signed version" in html  # fingerprint does not verify


def test_the_vote_page_loads_the_device_side_crypto(app):
    from app.election.r10_lock import lock_election
    db.session.execute(text("UPDATE elections SET opens_at = '2999-01-01 00:00:00', closes_at = '2999-01-02 00:00:00'"))
    db.session.commit()
    lock_election({"id": "u-delegate", "role": "delegate"}, "e1")
    db.session.execute(text("UPDATE elections SET status = 'OPEN' WHERE id = 'e1'"))
    db.session.commit()
    html = signed_in(app, "voter").get("/vote/e1").get_data(as_text=True)
    assert "ballot-form" in html and "/static/js/evp-crypto.js" in html and "/static/js/vote.js" in html


def test_demo_election_command_adds_a_draft_election(app):
    out = app.test_cli_runner().invoke(args=["ui", "demo-election"], input="5\n10\n")
    assert out.exit_code == 0 and "Lock it before it opens" in out.output
    count = db.session.execute(text("SELECT COUNT(*) FROM elections WHERE status = 'DRAFT' AND name LIKE 'Demo election%'")).scalar()
    assert count == 1
