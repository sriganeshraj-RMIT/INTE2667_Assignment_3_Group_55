"""R2 - Verified enrolment and address changes.

Letters are caught instead of sent (the `letters` fixture), and audit() is replaced so tests can see what
was logged. Acting as a user works like the other teams' tests: current_user is replaced in the module.
The last tests switch the real sign-in checks on to prove the routes are protected.
"""
import re
import time
import uuid
from datetime import date, timedelta

import pytest
from argon2 import PasswordHasher

from app import create_app
from app.auth.models import Account
from app.common.crypto import keyed_hash
from app.enrolment import r02_enrolment as r02
from app.enrolment.models import Elector
from app.enrolment.r02_models import EnrolmentCode, IdentityRecord, PostcodeDivision
from app.extensions import db

MODULE = "app.enrolment.r02_enrolment"

OFFICER = {"id": "u-officer-1", "role": "officer", "division": "Melbourne", "state": "VIC"}
VOTER = {"id": "u-voter-1", "role": "voter", "division": "Melbourne", "state": "VIC"}
OTHER_VOTER = {"id": "u-voter-2", "role": "voter", "division": "Melbourne", "state": "VIC"}

TAYLOR = {"given_name": "Taylor", "family_name": "Morgan", "dob": "1995-02-17",
          "doc_type": "DRIVER_LICENCE", "doc_number": "DL7654321",
          "address_line": "22 Lygon St", "suburb": "Carlton", "postcode": "3053", "email": "taylor@evp.test"}
FAKE = {**TAYLOR, "given_name": "Made", "family_name": "Up", "doc_number": "ZZ0000000"}
ALEX_DOC = {"doc_type": "PASSPORT", "doc_number": "PA1234567"}
NEW_ADDRESS = {"address_line": "80 Chapel St", "suburb": "Prahran", "postcode": "3181"}


@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True, R2_MIN_RESPONSE_SECONDS=0)
    with app.app_context():
        db.create_all()
        seed()
        yield app
        db.session.remove()


def seed():
    people = [("Alex", "Citizen", "1990-04-12", "PASSPORT", "PA1234567", True),
              ("Taylor", "Morgan", "1995-02-17", "DRIVER_LICENCE", "DL7654321", True),
              ("Casey", "Lee", "2003-11-02", "PASSPORT", "PB2468135", True),
              ("Robin", "Visitor", "1988-06-09", "PASSPORT", "PX9999999", False),
              ("Kid", "Young", (date.today() - timedelta(days=365 * 15)).isoformat(), "PASSPORT", "PK1111111", True)]
    for given, family, dob, doc_type, number, citizen in people:
        db.session.add(IdentityRecord(id=str(uuid.uuid4()), given_name=given, family_name=family,
                                      dob=date.fromisoformat(dob), doc_type=doc_type, doc_number=number,
                                      citizen=citizen))
    for postcode, division in (("3000", "Melbourne"), ("3053", "Melbourne"), ("3181", "Macnamara")):
        db.session.add(PostcodeDivision(postcode=postcode, division=division, state="VIC"))
    db.session.add(Elector(id="elector-alex", given_name="Alex", family_name="Citizen", dob=date(1990, 4, 12),
                           address_line="1 Swanston St", suburb="Melbourne", postcode="3000", state="VIC",
                           division="Melbourne", status="ENROLLED", account_id=VOTER["id"]))
    db.session.commit()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


@pytest.fixture
def letters(monkeypatch):
    sent = []
    monkeypatch.setattr(f"{MODULE}._deliver_letter",
                        lambda line, suburb, postcode, text: sent.append({"postcode": postcode, "text": text}))
    return sent


def act_as(monkeypatch, user):
    monkeypatch.setattr(f"{MODULE}.current_user", lambda: user)


def from_letter(letter):
    """The reference and code printed on a letter."""
    return (re.search(r"Reference: (\S+)", letter["text"]).group(1),
            re.search(r"Code: (\S+)", letter["text"]).group(1))


def taylor():
    return db.session.query(Elector).filter_by(family_name="Morgan").first()


def apply_taylor(client, letters):
    client.post("/enrolment/apply", json=TAYLOR)
    return from_letter(letters[-1])


# ---------------------------------------------------------------- enrolment needs both checks
def test_a_verified_application_posts_a_code_to_the_address_not_the_email(client, audit_log, letters):
    resp = client.post("/enrolment/apply", json=TAYLOR)
    assert resp.status_code == 202
    assert len(letters) == 1 and letters[0]["postcode"] == "3053"
    assert "taylor@evp.test" not in letters[0]["text"]
    assert taylor().status == "PENDING"                         # not on the roll until the code is used


def test_entering_the_code_from_the_letter_enrols_the_person(client, audit_log, letters):
    reference, code = apply_taylor(client, letters)
    resp = client.post("/enrolment/confirm", json={"reference": reference, "code": code})
    assert resp.status_code == 200
    assert taylor().status == "ENROLLED" and taylor().division == "Melbourne"
    assert audit_log[-1][0] == "ENROLMENT_CODE_REDEEMED"


def test_the_public_reply_is_identical_whether_or_not_the_identity_matched(client, audit_log, letters):
    verified = client.post("/enrolment/apply", json=TAYLOR)
    made_up = client.post("/enrolment/apply", json=FAKE)
    assert verified.status_code == made_up.status_code == 202
    assert verified.get_data() == made_up.get_data()
    assert len(letters) == 1                                     # only the real person gets a letter


@pytest.mark.parametrize("details, outcome", [
    (FAKE, "NOT_VERIFIED"),                                                        # made-up identity
    ({**TAYLOR, "dob": "1995-02-18"}, "NOT_VERIFIED"),                             # stolen doc, wrong DOB
    ({**TAYLOR, "given_name": "Robin", "family_name": "Visitor", "dob": "1988-06-09",
      "doc_type": "PASSPORT", "doc_number": "PX9999999"}, "NOT_VERIFIED"),         # not a citizen
    ({**TAYLOR, "given_name": "Kid", "family_name": "Young",
      "dob": (date.today() - timedelta(days=365 * 15)).isoformat(),
      "doc_type": "PASSPORT", "doc_number": "PK1111111"}, "NOT_ELIGIBLE"),         # under 16
    ({**TAYLOR, "postcode": "9999"}, "ADDRESS_NOT_RECOGNISED"),
])
def test_unverified_applications_create_nothing(app, audit_log, letters, details, outcome):
    assert r02.apply_for_enrolment(details) == outcome
    assert taylor() is None and letters == []
    assert audit_log[-1] == ("ENROLMENT_APPLIED", "anonymous", {"outcome": outcome, "channel": "online"})


def test_the_same_identity_cannot_be_enrolled_twice(client, audit_log, letters):
    reference, code = apply_taylor(client, letters)
    client.post("/enrolment/confirm", json={"reference": reference, "code": code})
    second = {**TAYLOR, "address_line": "9 Other St"}
    assert r02.apply_for_enrolment(second) == "ALREADY_ENROLLED"
    assert len(letters) == 1 and db.session.query(Elector).filter_by(family_name="Morgan").count() == 1


def test_the_document_number_and_code_are_never_stored(client, audit_log, letters):
    reference, code = apply_taylor(client, letters)
    row = taylor()
    assert row.doc_hash == keyed_hash("DRIVER_LICENCE:DL7654321")
    stored = " ".join(str(v) for v in vars(row).values()) + " ".join(
        str(v) for v in vars(db.session.get(EnrolmentCode, reference)).values())
    assert "DL7654321" not in stored and code not in stored


# ---------------------------------------------------------------- the code is single-use and hard to guess
def test_a_code_works_only_once(client, audit_log, letters):
    reference, code = apply_taylor(client, letters)
    assert client.post("/enrolment/confirm", json={"reference": reference, "code": code}).status_code == 200
    again = client.post("/enrolment/confirm", json={"reference": reference, "code": code})
    assert again.status_code == 400 and again.get_json()["error"] == "CODE_INVALID"


def test_five_wrong_codes_lock_the_letter(client, audit_log, letters):
    reference, code = apply_taylor(client, letters)
    for _ in range(r02.MAX_ATTEMPTS):
        resp = client.post("/enrolment/confirm", json={"reference": reference, "code": "WRONG23456"})
        assert resp.get_json()["error"] == "CODE_INVALID"
    locked = client.post("/enrolment/confirm", json={"reference": reference, "code": code})
    assert locked.status_code == 400 and taylor().status == "PENDING"
    assert audit_log.count(("ENROLMENT_CODE_REJECTED", "anonymous", {"reference": reference})) == 5


def test_an_expired_code_is_refused(client, audit_log, letters, monkeypatch):
    reference, code = apply_taylor(client, letters)
    later = r02.now() + timedelta(days=r02.CODE_DAYS, seconds=1)
    monkeypatch.setattr(f"{MODULE}.now", lambda: later)
    assert client.post("/enrolment/confirm", json={"reference": reference, "code": code}).status_code == 400
    assert taylor().status == "PENDING"


def test_refusals_do_not_say_why(client, audit_log, letters):
    reference, code = apply_taylor(client, letters)
    unknown = client.post("/enrolment/confirm", json={"reference": str(uuid.uuid4()), "code": code})
    wrong = client.post("/enrolment/confirm", json={"reference": reference, "code": "WRONG23456"})
    client.post("/enrolment/confirm", json={"reference": reference, "code": code})
    used = client.post("/enrolment/confirm", json={"reference": reference, "code": code})
    assert unknown.get_data() == wrong.get_data() == used.get_data()


def test_an_address_change_code_cannot_finish_an_enrolment(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, VOTER)
    client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS})
    reference, code = from_letter(letters[-1])
    assert client.post("/enrolment/confirm", json={"reference": reference, "code": code}).status_code == 400


@pytest.mark.parametrize("bad", [
    {**TAYLOR, "family_name": "' OR 1=1 --"},
    {**TAYLOR, "address_line": "<script>alert(1)</script>"},
    {**TAYLOR, "doc_type": "LIBRARY_CARD"},
    {**TAYLOR, "role": "admin"},                                  # extra fields are refused
])
def test_bad_input_is_refused(client, audit_log, letters, bad):
    assert client.post("/enrolment/apply", json=bad).status_code == 400
    assert letters == []


# ---------------------------------------------------------------- officers register citizens
def test_an_officer_registers_a_citizen_in_their_division(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, OFFICER)
    resp = client.post("/enrolment/officer/register", json=TAYLOR)
    assert resp.status_code == 202 and resp.get_json()["outcome"] == "LETTER_POSTED"
    assert audit_log[-1] == ("ENROLMENT_APPLIED", OFFICER["id"], {"outcome": "LETTER_POSTED", "channel": "officer"})


def test_an_officer_is_told_when_identity_fails(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, OFFICER)
    resp = client.post("/enrolment/officer/register", json=FAKE)
    assert resp.status_code == 422 and resp.get_json()["error"] == "NOT_VERIFIED"


def test_an_officer_cannot_register_someone_in_another_division(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, OFFICER)
    resp = client.post("/enrolment/officer/register", json={**TAYLOR, **NEW_ADDRESS})     # Macnamara
    assert resp.status_code == 403 and letters == []
    assert audit_log[-1][0] == "ENROLMENT_REGISTER_REFUSED"


# ---------------------------------------------------------------- address changes
def test_an_address_change_is_confirmed_at_the_new_address(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, VOTER)
    assert client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS}).status_code == 202
    alex = db.session.get(Elector, "elector-alex")
    assert alex.postcode == "3000"                               # nothing changes before the code
    assert letters[-1]["postcode"] == "3181"
    reference, code = from_letter(letters[-1])

    resp = client.post("/enrolment/address-change/confirm", json={"reference": reference, "code": code})
    assert resp.status_code == 200
    alex = db.session.get(Elector, "elector-alex")
    assert (alex.postcode, alex.division) == ("3181", "Macnamara")
    assert letters[-1]["postcode"] == "3000"                     # a notice goes to the old address
    assert "changed" in letters[-1]["text"]


def test_an_address_change_needs_the_voters_own_document(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, VOTER)
    resp = client.post("/enrolment/address-change",
                       json={"doc_type": "DRIVER_LICENCE", "doc_number": "DL7654321", **NEW_ADDRESS})
    assert resp.status_code == 422 and resp.get_json()["error"] == "IDENTITY_NOT_VERIFIED"
    assert letters == [] and audit_log[-1][0] == "ENROLMENT_ADDRESS_CHANGE_REFUSED"


def test_another_account_cannot_use_the_address_change_code(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, VOTER)
    client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS})
    reference, code = from_letter(letters[-1])
    act_as(monkeypatch, OTHER_VOTER)
    resp = client.post("/enrolment/address-change/confirm", json={"reference": reference, "code": code})
    assert resp.status_code == 403
    assert db.session.get(Elector, "elector-alex").postcode == "3000"


def test_a_new_request_cancels_the_earlier_letter(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, VOTER)
    client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS})
    first = from_letter(letters[-1])
    client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS, "address_line": "81 Chapel St"})
    resp = client.post("/enrolment/address-change/confirm", json={"reference": first[0], "code": first[1]})
    assert resp.status_code == 400


def test_a_voter_without_an_enrolment_cannot_ask(client, audit_log, letters, monkeypatch):
    act_as(monkeypatch, OTHER_VOTER)
    assert client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS}).status_code == 404


# ---------------------------------------------------------------- the real sign-in checks
def signed_in(client, app, account_id, role, mfa=True):
    with app.app_context():
        db.session.add(Account(id=account_id, email=f"{account_id}@evp.test",
                               password_hash=PasswordHasher().hash("not used here"), role=role,
                               division="Melbourne", state="VIC", status="ACTIVE"))
        db.session.commit()
    with client.session_transaction() as s:
        s["user_id"], s["last_seen"] = account_id, int(time.time())
        if mfa:
            s["mfa_user"], s["mfa_at"] = account_id, int(time.time())


def test_officer_registration_needs_sign_in(app, client, letters):
    app.config.update(LOGIN_ENFORCE=True)
    assert client.post("/enrolment/officer/register", json=TAYLOR).status_code == 401


def test_a_voter_cannot_use_the_officer_route(app, client, audit_log, letters):
    app.config.update(LOGIN_ENFORCE=True)
    signed_in(client, app, "u-real-voter", "voter")
    resp = client.post("/enrolment/officer/register", json=TAYLOR)
    assert resp.status_code == 403 and letters == []


def test_an_address_change_needs_the_second_sign_in_step(app, client, letters):
    app.config.update(LOGIN_ENFORCE=True, MFA_ENFORCE=True)
    signed_in(client, app, "u-real-voter", "voter", mfa=False)
    assert client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS}).status_code == 401
