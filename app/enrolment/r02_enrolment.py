"""R2 - Verified enrolment and address changes.

Nobody gets onto the roll, and no enrolled address changes, unless two checks pass:

  1. IDENTITY: the person's name, date of birth and identity document must match the official identity
     source (mocked by the identity_records table, which only answers yes/no), and they must be a
     citizen aged 16 or over. Only a keyed hash of the document is kept on the roll (R9), and the hash is
     unique, so the same identity cannot be enrolled twice.
  2. ADDRESS: a single-use code is "posted" to the address (a letter sent through MailHog, addressed to
     the resident at that address, NOT to the applicant's email). Nothing takes effect until the code is
     entered, so someone using a stolen identity cannot enrol it at an address they cannot receive mail at.

Codes: 10 characters, random (secrets), stored only as a keyed hash, single-use, valid for 14 days
(post is slow), locked after 5 wrong tries. Every refusal gives the same CODE_INVALID answer, so the
reply never says whether a reference exists, has expired or was used.

Routes (all under /enrolment):
  POST /apply                     anyone       - self-enrolment; same reply whatever the outcome
  POST /officer/register          officer      - an AEC employee registers a citizen (own division only)
  POST /confirm                   anyone       - reference + code from the letter -> ENROLLED
  POST /address-change            voter + MFA  - re-checks identity, posts a code to the NEW address
  POST /address-change/confirm    voter + MFA  - the code moves the enrolment; a notice goes to the old address
"""
import hmac
import os
import secrets
import smtplib
import threading
import time
import uuid
from datetime import date, timedelta
from email.message import EmailMessage

from flask import current_app, jsonify, request
from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError

from . import bp
from .models import Elector
from .r02_models import EnrolmentCode, IdentityRecord, PostcodeDivision
from .r15_harvest import NAME
from app.auth.r14_models import now
from app.common.audit import audit
from app.common.auth import current_user, login_required, mfa_required, role_required
from app.common.crypto import keyed_hash
from app.common.validate import validate
from app.extensions import db

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"      # no 0/O or 1/I, which are easy to misread on paper
CODE_LENGTH = 10
CODE_DAYS = 14
MAX_ATTEMPTS = 5
MIN_AGE = 16
MIN_RESPONSE_SECONDS = 0.5
DOC_TYPES = ["PASSPORT", "DRIVER_LICENCE"]

APPLY_REPLY = ("Thank you. If your details can be verified, a letter with a confirmation code will be posted "
               "to the address you gave. Your enrolment starts when you enter that code.")
CODE_INVALID = ("CODE_INVALID", "That reference and code do not match, or the code has expired or been used.", 400)

IDENTITY_FIELDS = {
    "doc_type":   {"type": str, "allowed": DOC_TYPES, "required": True},
    "doc_number": {"type": str, "pattern": r"[A-Za-z0-9]{6,12}", "required": True},
}
ADDRESS_FIELDS = {
    "address_line": {"type": str, "pattern": r"[A-Za-z0-9][A-Za-z0-9 ,.'/\-]{0,199}", "max_length": 200,
                     "required": True},
    "suburb":       {"type": str, "pattern": NAME, "max_length": 100, "required": True},
    "postcode":     {"type": str, "pattern": r"\d{4}", "required": True},
}
APPLY_SCHEMA = {
    "given_name":  {"type": str, "pattern": NAME, "max_length": 100, "required": True},
    "family_name": {"type": str, "pattern": NAME, "max_length": 100, "required": True},
    "dob":         {"type": str, "pattern": r"\d{4}-\d{2}-\d{2}", "required": True},
    "email":       {"type": str, "pattern": r"[^@\s]{1,64}@[^@\s]{1,180}\.[A-Za-z]{2,}", "max_length": 255},
    **IDENTITY_FIELDS,
    **ADDRESS_FIELDS,
}
ADDRESS_CHANGE_SCHEMA = {**IDENTITY_FIELDS, **ADDRESS_FIELDS}
CONFIRM_SCHEMA = {
    "reference": {"type": str, "pattern": r"[0-9a-f\-]{36}", "required": True},
    "code":      {"type": str, "pattern": r"[A-Za-z0-9]{10}", "required": True},
}


class EnrolmentError(Exception):
    """A refusal that is turned into the team's error JSON: {"error": CODE, "message": text}."""

    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


# ------------------------------------------------------------------ checks
def _parse_dob(text):
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise EnrolmentError("VALIDATION_FAILED", "dob is not a real date", 400)


def _age(dob, today):
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))


def identity_matches(given, family, dob, doc_type, doc_number):
    """The mock identity check. Like the real verification service it only answers yes or no."""
    record = (db.session.query(IdentityRecord)
              .filter(func.lower(IdentityRecord.given_name) == given.lower(),
                      func.lower(IdentityRecord.family_name) == family.lower(),
                      IdentityRecord.dob == dob,
                      IdentityRecord.doc_type == doc_type,
                      IdentityRecord.doc_number == doc_number.upper())
              .first())
    return record is not None and bool(record.citizen)


def doc_hash(doc_type, doc_number):
    """What the roll keeps instead of the document number (R9)."""
    return keyed_hash(f"{doc_type}:{doc_number.upper()}")


def _place(postcode):
    return db.session.get(PostcodeDivision, postcode)


# ------------------------------------------------------------------ codes and letters
def _new_code(elector_id, purpose, data, place):
    """Creates a code row (not yet committed). Returns (row, the plain code for the letter)."""
    reference = str(uuid.uuid4())
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    row = EnrolmentCode(id=reference, elector_id=elector_id, purpose=purpose,
                        code_hash=keyed_hash(f"{reference}:{code}"),
                        new_address_line=data["address_line"], new_suburb=data["suburb"],
                        new_postcode=data["postcode"], new_state=place.state, new_division=place.division,
                        expires_at=now() + timedelta(days=CODE_DAYS), attempts=0)
    db.session.add(row)
    return row, code


def _send_letter(address_line, suburb, postcode, text):
    msg = EmailMessage()
    msg["From"], msg["Subject"] = "letters@aec.evp.test", "Letter from the Australian Electoral Commission"
    msg["To"] = f"resident.{postcode}@post.evp.test"           # "posted" to the address, not to an email
    msg.set_content(f"To the resident at\n{address_line}\n{suburb} {postcode}\n\n{text}\n")
    host, port = os.environ.get("MAIL_HOST", "localhost"), int(os.environ.get("MAIL_PORT", "1025"))
    with smtplib.SMTP(host, port, timeout=5) as smtp:
        smtp.send_message(msg)


def _deliver_letter(address_line, suburb, postcode, text):
    """Sends in the background so the reply time does not depend on the outcome."""
    def send():
        try:
            _send_letter(address_line, suburb, postcode, text)
        except (OSError, smtplib.SMTPException):
            print("[R2] letter could not be sent")                 # no address or code in the log
    threading.Thread(target=send, daemon=True).start()


def _code_letter(row, code, purpose):
    what = "finish your enrolment" if purpose == "ENROL" else "confirm your new enrolled address"
    _deliver_letter(row.new_address_line, row.new_suburb, row.new_postcode,
                    f"To {what}, enter this reference and code within {CODE_DAYS} days.\n"
                    f"Reference: {row.id}\nCode: {code}\n\n"
                    "If you did not ask for this, ignore this letter and nothing will change.")


# ------------------------------------------------------------------ enrolment
def apply_for_enrolment(data, officer=None):
    """Runs both checks. Returns one outcome: LETTER_POSTED, NOT_VERIFIED, NOT_ELIGIBLE,
    ADDRESS_NOT_RECOGNISED or ALREADY_ENROLLED. An officer outside their division gets a 403."""
    dob = _parse_dob(data["dob"])
    place = _place(data["postcode"])
    actor = officer["id"] if officer else "anonymous"
    if officer and (not officer.get("division") or (place and place.division != officer["division"])):
        audit("ENROLMENT_REGISTER_REFUSED", actor_id=actor, details={"reason": "other_division"})
        raise EnrolmentError("FORBIDDEN", "You can only register electors in your own division.", 403)

    hashed = doc_hash(data["doc_type"], data["doc_number"])
    existing = db.session.query(Elector).filter_by(doc_hash=hashed).first()
    if _age(dob, now().date()) < MIN_AGE:
        outcome = "NOT_ELIGIBLE"
    elif not identity_matches(data["given_name"], data["family_name"], dob, data["doc_type"], data["doc_number"]):
        outcome = "NOT_VERIFIED"
    elif place is None:
        outcome = "ADDRESS_NOT_RECOGNISED"
    elif existing is not None and existing.status == "ENROLLED":
        outcome = "ALREADY_ENROLLED"
    else:
        outcome = _start_enrolment(data, dob, hashed, place, existing)

    audit("ENROLMENT_APPLIED", actor_id=actor,
          details={"outcome": outcome, "channel": "officer" if officer else "online"})
    return outcome


def _start_enrolment(data, dob, hashed, place, existing):
    """Creates the PENDING elector (or reuses a pending one) and posts the code."""
    if existing is None:
        existing = Elector(id=str(uuid.uuid4()), given_name=data["given_name"], family_name=data["family_name"],
                           dob=dob, address_line=data["address_line"], suburb=data["suburb"],
                           postcode=data["postcode"], state=place.state, division=place.division,
                           email=data.get("email"), status="PENDING", doc_hash=hashed, created_at=now())
        db.session.add(existing)
    row, code = _new_code(existing.id, "ENROL", data, place)
    try:
        db.session.commit()
    except IntegrityError:                     # the same document enrolled at the same moment
        db.session.rollback()
        return "ALREADY_ENROLLED"
    _code_letter(row, code, "ENROL")
    return "LETTER_POSTED"


def redeem_code(reference, code, purpose, voter=None):
    """Checks a posted code and applies it. Returns the elector. Any problem -> CODE_INVALID."""
    row = db.session.get(EnrolmentCode, reference)
    if (row is None or row.purpose != purpose or row.used_at is not None
            or row.expires_at < now() or row.attempts >= MAX_ATTEMPTS):
        raise EnrolmentError(*CODE_INVALID)
    elector = db.session.get(Elector, row.elector_id)
    actor = voter["id"] if voter else "anonymous"
    if purpose == "ADDRESS" and (voter is None or elector is None or elector.account_id != voter["id"]):
        audit("ENROLMENT_CODE_REFUSED", actor_id=actor, details={"reference": reference, "reason": "not_owner"})
        raise EnrolmentError("FORBIDDEN", "This address change belongs to another account.", 403)

    if not hmac.compare_digest(row.code_hash, keyed_hash(f"{reference}:{code.upper()}")):
        db.session.execute(update(EnrolmentCode).where(EnrolmentCode.id == reference)
                           .values(attempts=EnrolmentCode.attempts + 1))
        db.session.commit()
        audit("ENROLMENT_CODE_REJECTED", actor_id=actor, details={"reference": reference})
        raise EnrolmentError(*CODE_INVALID)

    claimed = db.session.execute(                # only one request can ever use the code
        update(EnrolmentCode)
        .where(EnrolmentCode.id == reference, EnrolmentCode.used_at.is_(None),
               EnrolmentCode.attempts < MAX_ATTEMPTS)
        .values(used_at=now()).execution_options(synchronize_session=False))
    if claimed.rowcount != 1 or (purpose == "ENROL" and elector.status != "PENDING"):
        db.session.rollback()
        raise EnrolmentError(*CODE_INVALID)

    old = (elector.address_line, elector.suburb, elector.postcode)
    elector.address_line, elector.suburb, elector.postcode = row.new_address_line, row.new_suburb, row.new_postcode
    elector.state, elector.division = row.new_state, row.new_division
    if purpose == "ENROL":
        elector.status = "ENROLLED"
    db.session.execute(                          # any other letters for the same purpose stop working
        update(EnrolmentCode)
        .where(EnrolmentCode.elector_id == elector.id, EnrolmentCode.purpose == purpose,
               EnrolmentCode.used_at.is_(None))
        .values(used_at=now()).execution_options(synchronize_session=False))
    db.session.commit()

    if purpose == "ADDRESS":
        _deliver_letter(*old, "The enrolled address for the person at this address has been changed. "
                              "If this was not you, contact the AEC straight away.")
    audit("ENROLMENT_CODE_REDEEMED", actor_id=actor, details={"purpose": purpose, "elector_id": elector.id})
    return elector


# ------------------------------------------------------------------ address change
def request_address_change(user, data):
    """A signed-in voter asks to move. Identity is checked again and a code is posted to the new address."""
    if not user or user.get("role") != "voter":
        raise EnrolmentError("FORBIDDEN", "Only a voter can change their own address.", 403)
    elector = db.session.query(Elector).filter_by(account_id=user["id"], status="ENROLLED").first()
    if elector is None:
        raise EnrolmentError("NOT_ENROLLED", "This account is not linked to an enrolment.", 404)

    same_person = identity_matches(elector.given_name, elector.family_name, elector.dob,
                                   data["doc_type"], data["doc_number"])
    if not same_person or (elector.doc_hash and elector.doc_hash != doc_hash(data["doc_type"], data["doc_number"])):
        audit("ENROLMENT_ADDRESS_CHANGE_REFUSED", actor_id=user["id"], details={"reason": "identity"})
        raise EnrolmentError("IDENTITY_NOT_VERIFIED", "The identity document does not match this enrolment.", 422)
    place = _place(data["postcode"])
    if place is None:
        raise EnrolmentError("ADDRESS_NOT_RECOGNISED", "That postcode is not recognised.", 422)

    db.session.execute(                          # an earlier, unfinished request stops working
        update(EnrolmentCode)
        .where(EnrolmentCode.elector_id == elector.id, EnrolmentCode.purpose == "ADDRESS",
               EnrolmentCode.used_at.is_(None))
        .values(used_at=now()).execution_options(synchronize_session=False))
    row, code = _new_code(elector.id, "ADDRESS", data, place)
    db.session.commit()
    _code_letter(row, code, "ADDRESS")
    audit("ENROLMENT_ADDRESS_CHANGE_REQUESTED", actor_id=user["id"], details={"elector_id": elector.id})
    return row


# ------------------------------------------------------------------ routes
OFFICER_REPLIES = {
    "LETTER_POSTED":          (202, "Identity verified. A confirmation letter has been posted to the address."),
    "NOT_VERIFIED":           (422, "The details do not match the identity source, or the person is not a citizen."),
    "NOT_ELIGIBLE":           (422, "The person is under 16 and cannot enrol yet."),
    "ADDRESS_NOT_RECOGNISED": (422, "That postcode is not recognised."),
    "ALREADY_ENROLLED":       (409, "This person is already enrolled."),
}


@bp.post("/apply")                               # final URL: /enrolment/apply (public)
def enrolment_apply():
    started = time.monotonic()
    data = validate(APPLY_SCHEMA, request.get_json(silent=True))
    try:
        apply_for_enrolment(data)
    except EnrolmentError as e:
        return error_response(e)
    wait = current_app.config.get("R2_MIN_RESPONSE_SECONDS", MIN_RESPONSE_SECONDS) - (time.monotonic() - started)
    if wait > 0:
        time.sleep(wait)
    return jsonify({"message": APPLY_REPLY}), 202     # the same reply whatever happened


@bp.post("/officer/register")
@login_required
@role_required("officer")
def enrolment_officer_register():
    data = validate(APPLY_SCHEMA, request.get_json(silent=True))
    try:
        outcome = apply_for_enrolment(data, officer=current_user())
    except EnrolmentError as e:
        return error_response(e)
    status, message = OFFICER_REPLIES[outcome]
    if status == 202:
        return jsonify({"outcome": outcome, "message": message}), 202
    return jsonify({"error": outcome, "message": message}), status


@bp.post("/confirm")
def enrolment_confirm():
    data = validate(CONFIRM_SCHEMA, request.get_json(silent=True))
    try:
        redeem_code(data["reference"], data["code"], "ENROL")
    except EnrolmentError as e:
        return error_response(e)
    return jsonify({"message": "You are now enrolled."})


@bp.post("/address-change")
@login_required
@role_required("voter")
@mfa_required
def enrolment_address_change():
    data = validate(ADDRESS_CHANGE_SCHEMA, request.get_json(silent=True))
    try:
        request_address_change(current_user(), data)
    except EnrolmentError as e:
        return error_response(e)
    return jsonify({"message": "A letter with a confirmation code has been posted to your new address."}), 202


@bp.post("/address-change/confirm")
@login_required
@role_required("voter")
@mfa_required
def enrolment_address_change_confirm():
    data = validate(CONFIRM_SCHEMA, request.get_json(silent=True))
    try:
        redeem_code(data["reference"], data["code"], "ADDRESS", voter=current_user())
    except EnrolmentError as e:
        return error_response(e)
    return jsonify({"message": "Your enrolled address has been updated."})
