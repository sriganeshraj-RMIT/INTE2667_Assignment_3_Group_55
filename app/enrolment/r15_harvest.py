"""R15 - No harvesting of the voter list.

Stops anyone collecting names and addresses in bulk, or finding out who is enrolled. Four parts:

  1. Public enrolment check (POST /enrolment/check)
       - The reply is the SAME whether or not the details match an enrolment. The real answer is
         emailed to the contact details on file, so only the actual person learns it.
       - The work is the same on both paths and the reply is padded to a minimum time, so the
         response time does not give the answer away either.
       - Rate limited in Redis: per client IP (5 an hour) and per person looked up (3 a day), so one
         person cannot be probed from many addresses. Keys hold only keyed hashes, never raw details.
  2. Staff voter-list search (POST /enrolment/voters/search)
       - Officers only, and only inside their own division (deny by default if they have none).
       - Every search is written to the audit log with the fields used and the number of results,
         never the values searched for.
  3. Large downloads blocked
       - There is no export or "list everything" route and no paging. A search needs an exact family
         name plus a suburb or postcode, and returns at most 50 rows.
  4. More than 1,000 records read in one minute
       - A Redis counter per account per minute. The request that would pass 1,000 is refused, the
         VOTERLIST_BULK_READ_ALERT audit event is written (R11 raises the alert from it), and the
         account is blocked for the rest of that minute.

Redis being unreachable makes these routes fail (HTTP 500) rather than run without limits.
Behind the R16 proxy, request.remote_addr is the proxy unless the app is told to trust its
X-Forwarded-For header; that setting belongs in the app factory (ask Jaswanth).
"""
import os
import smtplib
import threading
import time
from datetime import date
from email.message import EmailMessage

from flask import current_app, jsonify, request
from sqlalchemy import func

from . import bp
from .models import Elector
from app.common.audit import audit
from app.common.auth import current_user, login_required, role_required
from app.common.crypto import keyed_hash
from app.common.validate import validate
from app.extensions import db, get_redis

LOOKUPS_PER_IP = 5                 # per hour
LOOKUPS_PER_PERSON = 3             # per day
IP_WINDOW_SECONDS = 60 * 60
PERSON_WINDOW_SECONDS = 24 * 60 * 60
SEARCH_MAX_RESULTS = 50
READS_PER_MINUTE_LIMIT = 1000
MIN_RESPONSE_SECONDS = 0.5         # the enrolment check never answers faster than this

NEUTRAL_REPLY = ("If these details match an enrolment, we have sent the result to the contact details "
                 "on the roll. If you do not hear from us, you may need to enrol.")

NAME = r"[A-Za-z][A-Za-z' \-]{0,99}"
CHECK_SCHEMA = {
    "given_name":  {"type": str, "pattern": NAME, "max_length": 100, "required": True},
    "family_name": {"type": str, "pattern": NAME, "max_length": 100, "required": True},
    "dob":         {"type": str, "pattern": r"\d{4}-\d{2}-\d{2}", "required": True},
    "postcode":    {"type": str, "pattern": r"\d{4}", "required": True},
}
SEARCH_SCHEMA = {
    "family_name": {"type": str, "pattern": NAME, "min_length": 3, "max_length": 100, "required": True},
    "given_name":  {"type": str, "pattern": NAME, "max_length": 100},
    "suburb":      {"type": str, "pattern": NAME, "max_length": 100},
    "postcode":    {"type": str, "pattern": r"\d{4}"},
    "limit":       {"type": int, "min": 1, "max": SEARCH_MAX_RESULTS, "default": 20},
}


class HarvestError(Exception):
    """A refusal that is turned into the team's error JSON: {"error": CODE, "message": text}."""

    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


def _now():
    """Seconds since 1970. A function so the tests can move the clock."""
    return time.time()


def _count(key, amount, window_seconds):
    """Adds amount to a Redis counter that disappears after window_seconds. Returns the new total."""
    r = get_redis()
    total = int(r.incrby(key, amount))
    if total == amount:                       # first use of this key: start its window
        r.expire(key, window_seconds)
    return total


# ------------------------------------------------------------------ 1. public enrolment check
def _send_status_email(to, division):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "no-reply@evp.test", to, "Your enrolment check"
    msg.set_content(f"Someone checked the enrolment of this address. You are enrolled in the division of "
                    f"{division}. If this was not you, no action is needed.")
    host, port = os.environ.get("MAIL_HOST", "localhost"), int(os.environ.get("MAIL_PORT", "1025"))
    with smtplib.SMTP(host, port, timeout=5) as smtp:
        smtp.send_message(msg)


def _deliver(to, division):
    """Sends the result in the background, so the reply does not wait for the mail server
    (waiting would make the enrolled path slower and give the answer away)."""
    def send():
        try:
            _send_status_email(to, division)
        except (OSError, smtplib.SMTPException):
            print("[R15] enrolment check email could not be sent")    # no address or details in the log
    threading.Thread(target=send, daemon=True).start()


def check_enrolment(details, client_ip):
    """Counts the lookup, then emails the real answer to an enrolled person. Always returns NEUTRAL_REPLY."""
    try:
        dob = date.fromisoformat(details["dob"])
    except ValueError:
        raise HarvestError("VALIDATION_FAILED", "dob is not a real date", 400)

    person = "|".join([details["family_name"].lower(), details["given_name"].lower(),
                       details["dob"], details["postcode"]])
    by_ip = _count(f"r15:lookup:ip:{keyed_hash(client_ip)}", 1, IP_WINDOW_SECONDS)
    by_person = _count(f"r15:lookup:person:{keyed_hash(person)}", 1, PERSON_WINDOW_SECONDS)
    if by_ip > LOOKUPS_PER_IP or by_person > LOOKUPS_PER_PERSON:
        audit("ENROLMENT_LOOKUP_RATE_LIMITED", actor_id="anonymous",
              details={"limit": "ip" if by_ip > LOOKUPS_PER_IP else "person"})
        raise HarvestError("RATE_LIMITED", "Too many enrolment checks. Please try again later.", 429)

    elector = (db.session.query(Elector)
               .filter(func.lower(Elector.family_name) == details["family_name"].lower(),
                       func.lower(Elector.given_name) == details["given_name"].lower(),
                       Elector.dob == dob,
                       Elector.postcode == details["postcode"],
                       Elector.status == "ENROLLED")
               .first())
    if elector is not None and elector.email:
        _deliver(elector.email, elector.division)
    audit("ENROLMENT_LOOKUP", actor_id="anonymous", details={})   # the outcome is not logged
    return NEUTRAL_REPLY


# ------------------------------------------------------------------ 2-4. staff voter-list search
def search_voters(user, filters):
    """Officer search inside their own division, capped at 50 rows and 1,000 rows a minute."""
    if not user or user.get("role") != "officer":
        audit("VOTERLIST_SEARCH_REFUSED", actor_id=(user or {}).get("id", "anonymous"),
              details={"role": (user or {}).get("role")})
        raise HarvestError("FORBIDDEN", "Only an electoral officer can search the voter list.", 403)
    if not user.get("division"):
        raise HarvestError("FORBIDDEN", "Your account is not assigned to a division.", 403)
    if not filters.get("suburb") and not filters.get("postcode"):
        raise HarvestError("FILTER_TOO_BROAD", "Add a suburb or postcode to the family name.", 400)

    read_key = f"r15:reads:{user['id']}:{int(_now() // 60)}"
    if int(get_redis().get(read_key) or 0) > READS_PER_MINUTE_LIMIT:
        raise HarvestError("BULK_READ_BLOCKED", "Too many records read. Wait a minute and try again.", 429)

    query = db.session.query(Elector).filter(
        Elector.division == user["division"],
        func.lower(Elector.family_name) == filters["family_name"].lower())
    if filters.get("given_name"):
        query = query.filter(func.lower(Elector.given_name) == filters["given_name"].lower())
    if filters.get("suburb"):
        query = query.filter(func.lower(Elector.suburb) == filters["suburb"].lower())
    if filters.get("postcode"):
        query = query.filter(Elector.postcode == filters["postcode"])
    rows = query.order_by(Elector.family_name, Elector.given_name, Elector.id).limit(filters["limit"]).all()

    total = _count(read_key, len(rows), 120)
    used = sorted(k for k in ("family_name", "given_name", "suburb", "postcode") if filters.get(k))
    audit("VOTERLIST_SEARCH", actor_id=user["id"], details={"fields": used, "results": len(rows)})
    if total > READS_PER_MINUTE_LIMIT:
        if total - len(rows) <= READS_PER_MINUTE_LIMIT:            # this request crossed the line: alert once
            audit("VOTERLIST_BULK_READ_ALERT", actor_id=user["id"],
                  details={"records_this_minute": total, "limit": READS_PER_MINUTE_LIMIT})
        raise HarvestError("BULK_READ_BLOCKED", "Too many records read. Wait a minute and try again.", 429)

    return [{"id": e.id, "given_name": e.given_name, "family_name": e.family_name,
             "address_line": e.address_line, "suburb": e.suburb, "postcode": e.postcode,
             "status": e.status} for e in rows]


# ------------------------------------------------------------------ routes
@bp.post("/check")                               # final URL: /enrolment/check (public)
def enrolment_check():
    started = time.monotonic()
    data = validate(CHECK_SCHEMA, request.get_json(silent=True))
    try:
        reply = check_enrolment(data, request.remote_addr or "unknown")
    except HarvestError as e:
        return error_response(e)
    wait = current_app.config.get("R15_MIN_RESPONSE_SECONDS", MIN_RESPONSE_SECONDS) - (time.monotonic() - started)
    if wait > 0:
        time.sleep(wait)
    return jsonify({"message": reply})


@bp.post("/voters/search")                       # final URL: /enrolment/voters/search
@login_required
@role_required("officer")
def voters_search():
    data = validate(SEARCH_SCHEMA, request.get_json(silent=True))
    try:
        results = search_voters(current_user(), data)
    except HarvestError as e:
        return error_response(e)
    return jsonify({"results": results, "count": len(results),
                    "truncated": len(results) == data["limit"]})
