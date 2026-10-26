"""R18 - CSRF, Content-Security-Policy, security headers and safe JSON errors."""
import re

import pytest
from flask import render_template, request

from app import create_app
from app.common.security import csrf_exempt
from app.common.validate import validate


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True

    @app.post("/_t/echo")
    def echo():
        return validate({"name": {"type": str, "max_length": 10, "required": True}}, request.get_json(silent=True))

    @app.post("/_t/exempt")
    @csrf_exempt
    def exempt():
        return {"ok": True}

    @app.get("/_t/boom")
    def boom():
        raise RuntimeError("SECRET-INTERNAL-DETAIL")

    @app.get("/_t/page")
    def page():
        return render_template("base.html")

    return app


@pytest.fixture
def strict(app):
    app.config["CSRF_ENFORCE"] = True
    return app


def get_token(client):
    return client.get("/csrf-token").get_json()["csrf_token"]


# ------------------------------------------------------------------ errors
def test_validation_errors_use_the_team_format(app):
    resp = app.test_client().post("/_t/echo", json={"name": "<script>EVIL-MARKER</script>"})
    body = resp.get_json()
    assert resp.status_code == 400 and set(body) == {"error", "message"}
    assert body["error"] == "VALIDATION_FAILED" and "EVIL-MARKER" not in body["message"]


def test_unknown_page_returns_json_404(app):
    resp = app.test_client().get("/nope")
    assert resp.status_code == 404 and resp.get_json()["error"] == "NOT_FOUND"


def test_wrong_method_returns_json_405_with_allow_header(app):
    resp = app.test_client().get("/_t/echo")
    assert resp.status_code == 405 and resp.get_json()["error"] == "METHOD_NOT_ALLOWED"
    assert "POST" in resp.headers["Allow"]


def test_malformed_json_is_a_clean_400(app):
    resp = app.test_client().post("/_t/echo", data="{broken", content_type="application/json")
    assert resp.status_code == 400 and resp.get_json()["error"] in ("VALIDATION_FAILED", "BAD_REQUEST")


def test_oversize_body_is_refused(app):
    app.config["MAX_CONTENT_LENGTH"] = 100
    resp = app.test_client().post("/_t/echo", json={"name": "x" * 500})
    assert resp.status_code == 413 and resp.get_json()["error"] == "PAYLOAD_TOO_LARGE"


def test_server_errors_do_not_leak_details_in_production(app):
    app.config["TESTING"] = False
    resp = app.test_client().get("/_t/boom")
    assert resp.status_code == 500 and resp.get_json() == {"error": "INTERNAL_ERROR", "message": "Something went wrong."}
    assert "SECRET-INTERNAL-DETAIL" not in resp.get_data(as_text=True)


def test_errors_are_visible_while_testing(app):
    with pytest.raises(RuntimeError):
        app.test_client().get("/_t/boom")


# ------------------------------------------------------------------ headers
def test_security_headers_are_on_every_response(app):
    h = app.test_client().get("/health").headers
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer" and h["Cache-Control"] == "no-store"
    csp = h["Content-Security-Policy"]
    for part in ("default-src 'self'", "object-src 'none'", "frame-ancestors 'none'", "form-action 'self'"):
        assert part in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp


def test_csp_nonce_is_fresh_for_every_response(app):
    client = app.test_client()
    nonces = {re.search(r"'nonce-([^']+)'", client.get("/health").headers["Content-Security-Policy"]).group(1)
              for _ in range(5)}
    assert len(nonces) == 5


def test_page_uses_the_same_nonce_as_the_header_and_has_a_csrf_meta_tag(app):
    client = app.test_client()
    resp = client.get("/_t/page")
    nonce = re.search(r"'nonce-([^']+)'", resp.headers["Content-Security-Policy"]).group(1)
    html = resp.get_data(as_text=True)
    assert f'nonce="{nonce}"' in html
    token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    assert token == get_token(client)
    assert "http-equiv" not in html                      # the policy comes from the header only


def test_hsts_only_over_https(app):
    client = app.test_client()
    assert "Strict-Transport-Security" not in client.get("/health").headers
    assert "Strict-Transport-Security" in client.get("/health", base_url="https://localhost").headers


# -------------------------------------------------------------------- CSRF
def test_csrf_is_off_while_testing_so_other_tests_keep_working(app):
    assert app.test_client().post("/_t/echo", json={"name": "Bob"}).status_code == 200


def test_post_without_a_token_is_refused(strict):
    resp = strict.test_client().post("/_t/echo", json={"name": "Bob"})
    assert resp.status_code == 403 and resp.get_json()["error"] == "CSRF_FAILED"


def test_post_with_the_right_token_works(strict):
    client = strict.test_client()
    resp = client.post("/_t/echo", json={"name": "Bob"}, headers={"X-CSRF-Token": get_token(client)})
    assert resp.status_code == 200


def test_form_field_token_also_works(strict):
    client = strict.test_client()
    resp = client.post("/_t/echo", data={"csrf_token": get_token(client)})
    assert resp.status_code == 400                       # passed CSRF, then failed validation (not JSON)


def test_wrong_token_is_refused(strict):
    client = strict.test_client()
    get_token(client)
    resp = client.post("/_t/echo", json={"name": "Bob"}, headers={"X-CSRF-Token": "wrong"})
    assert resp.status_code == 403


def test_a_token_from_another_session_is_refused(strict):
    token = get_token(strict.test_client())
    resp = strict.test_client().post("/_t/echo", json={"name": "Bob"}, headers={"X-CSRF-Token": token})
    assert resp.status_code == 403


def test_safe_methods_never_need_a_token(strict):
    assert strict.test_client().get("/health").status_code == 200


def test_exempt_views_skip_the_check(strict):
    assert strict.test_client().post("/_t/exempt").status_code == 200
