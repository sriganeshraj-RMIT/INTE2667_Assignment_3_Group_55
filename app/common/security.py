"""R18 - app-wide request and response hardening.

init_security(app) is called once from the app factory and gives every route:
  * CSRF protection for POST/PUT/PATCH/DELETE (token in the session, sent back in the
    X-CSRF-Token header or a csrf_token form field),
  * a Content-Security-Policy with a fresh nonce on every response, plus other security headers,
  * a size limit on request bodies,
  * JSON errors in the team format {"error": CODE, "message": text} that never leak internals.

For teammates:
  * In templates:  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                   <script nonce="{{ csp_nonce }}"> ... </script>
  * For JS/API clients: GET /csrf-token, then send it as the X-CSRF-Token header.
  * Machine-to-machine endpoints that are protected another way (for example a terminal using a
    client certificate) can opt out with @csrf_exempt. Use it rarely and say why in a comment.
  * CSRF is off while app.config["TESTING"] is True, so existing tests keep working. To test the
    protection itself set app.config["CSRF_ENFORCE"] = True.
"""
import hmac
import os
import secrets

from flask import current_app, g, jsonify, request, session
from werkzeug.exceptions import Forbidden, HTTPException

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DEFAULT_MAX_BODY = 5 * 1024 * 1024

_CODES = {400: "BAD_REQUEST", 401: "UNAUTHENTICATED", 403: "FORBIDDEN", 404: "NOT_FOUND",
          405: "METHOD_NOT_ALLOWED", 409: "CONFLICT", 413: "PAYLOAD_TOO_LARGE",
          415: "UNSUPPORTED_MEDIA_TYPE", 422: "UNPROCESSABLE", 429: "RATE_LIMITED"}
_TEXT = {400: "The request could not be understood.", 401: "Sign-in is required.",
         403: "You are not allowed to do this.", 404: "Not found.",
         405: "This method is not allowed here.", 409: "The request conflicts with the current state.",
         413: "The request is too large.", 415: "This content type is not supported.",
         422: "The request could not be processed.", 429: "Too many requests."}
_COPY_HEADERS = {"allow", "retry-after", "www-authenticate"}


class CsrfFailed(Forbidden):
    error_code = "CSRF_FAILED"
    description = "The security token is missing or wrong. Reload the page and try again."


def csrf_exempt(view):
    """Mark a view as not needing a CSRF token (see the module notes)."""
    view.csrf_exempt = True
    return view


def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def _csp(nonce):
    return ("default-src 'self'; "                       # the GUI serves Bootstrap and its scripts itself (/static)
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


def init_security(app):
    app.config.setdefault("MAX_CONTENT_LENGTH", int(os.environ.get("MAX_BODY_BYTES", DEFAULT_MAX_BODY)))
    app.config.setdefault("CSRF_ENFORCE", None)          # None = on, except while TESTING

    @app.before_request
    def _guard():
        g.csp_nonce = secrets.token_urlsafe(16)
        if request.method not in UNSAFE_METHODS:
            return
        enforce = current_app.config["CSRF_ENFORCE"]
        if enforce is None:
            enforce = not current_app.config.get("TESTING", False)
        if not enforce:
            return
        view = current_app.view_functions.get(request.endpoint)
        if view is not None and getattr(view, "csrf_exempt", False):
            return
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token") or ""
        expected = session.get("_csrf") or ""
        if not (sent and expected and hmac.compare_digest(sent, expected)):
            raise CsrfFailed()

    @app.context_processor
    def _template_helpers():
        return {"csp_nonce": getattr(g, "csp_nonce", ""), "csrf_token": csrf_token}

    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = _csp(getattr(g, "csp_nonce", ""))
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers.setdefault("Cache-Control", "no-store")
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.get("/csrf-token")
    def _csrf_token_route():
        return {"csrf_token": csrf_token()}

    @app.errorhandler(HTTPException)
    def _http_error(e):
        own_code = getattr(e, "error_code", None)
        code = own_code or _CODES.get(e.code, f"HTTP_{e.code}")
        message = e.description if own_code else _TEXT.get(e.code, "The request could not be completed.")
        resp = jsonify({"error": code, "message": message})
        resp.status_code = e.code
        for name, value in e.get_headers():
            if name.lower() in _COPY_HEADERS:
                resp.headers[name] = value
        return resp

    @app.errorhandler(Exception)
    def _server_error(e):
        if current_app.testing or current_app.debug:
            raise e                                       # show the real error while developing
        current_app.logger.exception("Unhandled error")   # details stay in the server log only
        resp = jsonify({"error": "INTERNAL_ERROR", "message": "Something went wrong."})
        resp.status_code = 500
        return resp
