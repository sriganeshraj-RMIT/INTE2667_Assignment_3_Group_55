"""R9 - Identity-document minimisation.

Uses the same seed people as the R2 tests. The audit log is the REAL one here (R17), so the "number appears
nowhere" test also checks the audit log.
"""
import io
import time

import pytest
from sqlalchemy import text

from app import create_app
from app.common.crypto import keyed_hash
from app.enrolment import r09_minimise as r09
from app.enrolment.models import Elector
from app.enrolment.r09_models import IdentityCheck
from app.extensions import db
from tests.test_r02_enrolment import ALEX_DOC, FAKE, NEW_ADDRESS, TAYLOR, VOTER, from_letter, seed

AUDITOR = {"id": "u-auditor-1", "role": "auditor", "division": None, "state": None}
OFFICER = {"id": "u-officer-1", "role": "officer", "division": "Melbourne", "state": "VIC"}
PERSONAL = ("Taylor", "Morgan", "Alex", "Citizen", "Lygon", "Swanston", "3053", "1995-02-17", "1990-04-12",
            "taylor@evp.test")


@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True, R2_MIN_RESPONSE_SECONDS=0)
    with app.app_context():
        db.create_all()
        seed()
        yield app
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def letters(monkeypatch):
    sent = []
    monkeypatch.setattr("app.enrolment.r02_enrolment._deliver_letter",
                        lambda line, suburb, postcode, text: sent.append({"postcode": postcode, "text": text}))
    return sent


def act_as(monkeypatch, user):
    monkeypatch.setattr("app.enrolment.r02_enrolment.current_user", lambda: user)
    monkeypatch.setattr("app.enrolment.r09_minimise.current_user", lambda: user)


def checks():
    return db.session.query(IdentityCheck).order_by(IdentityCheck.checked_at).all()


def taylor():
    return db.session.query(Elector).filter_by(family_name="Morgan").first()


# ---------------------------------------------------------------- scrambled number + result + reference
def test_a_successful_check_is_kept_as_hash_result_and_reference(client, letters):
    client.post("/enrolment/apply", json=TAYLOR)
    [check] = checks()
    assert check.doc_hash == keyed_hash("DRIVER_LICENCE:DL7654321")
    assert (check.doc_type, check.result, check.purpose) == ("DRIVER_LICENCE", "MATCH", "ENROL")
    assert len(check.id) == 36 and check.elector_id == taylor().id          # the reference, linked to the roll


def test_a_failed_check_is_kept_too(client, letters):
    client.post("/enrolment/apply", json=FAKE)
    [check] = checks()
    assert check.result == "NO_MATCH" and check.elector_id is None
    assert check.doc_hash == keyed_hash("DRIVER_LICENCE:ZZ0000000")


def test_an_officer_check_records_who_made_it(client, letters, monkeypatch):
    act_as(monkeypatch, OFFICER)
    client.post("/enrolment/officer/register", json=TAYLOR)
    assert checks()[0].checked_by == OFFICER["id"]


def test_address_change_checks_are_kept(client, letters, monkeypatch):
    act_as(monkeypatch, VOTER)
    client.post("/enrolment/address-change", json={"doc_type": "PASSPORT", "doc_number": "PB2468135", **NEW_ADDRESS})
    client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS})
    assert [(c.result, c.purpose, c.elector_id, c.checked_by) for c in checks()] == [
        ("NO_MATCH", "ADDRESS", "elector-alex", VOTER["id"]),
        ("MATCH", "ADDRESS", "elector-alex", VOTER["id"])]


def test_the_scrambled_number_cannot_be_checked_without_the_secret_key(app, client, letters):
    client.post("/enrolment/apply", json=TAYLOR)
    stored = checks()[0].doc_hash
    import hashlib
    assert stored != hashlib.sha256(b"DRIVER_LICENCE:DL7654321").hexdigest()   # a plain hash of a guess fails
    app.config["SECRET_KEY"] = "a-different-secret"
    assert keyed_hash("DRIVER_LICENCE:DL7654321") != stored                      # so does the wrong key


def test_the_document_number_is_stored_nowhere(app, client, letters, monkeypatch):
    """After enrolling, confirming, a failed check and an address change, scan EVERY table we own."""
    client.post("/enrolment/apply", json=TAYLOR)
    reference, code = from_letter(letters[-1])
    client.post("/enrolment/confirm", json={"reference": reference, "code": code})
    client.post("/enrolment/apply", json=FAKE)
    act_as(monkeypatch, VOTER)
    client.post("/enrolment/address-change", json={**ALEX_DOC, **NEW_ADDRESS})

    numbers = ("DL7654321", "ZZ0000000", "PA1234567")
    for bind in (None, "ballot"):
        engine = db.engines[bind]
        for table in db.metadata.sorted_tables:
            if table.info.get("bind_key", getattr(table, "bind_key", None)) not in (None, bind):
                continue
            if table.name == "identity_records":                 # the MOCK external identity service, not ours
                continue
            try:
                with engine.connect() as c:
                    rows = c.execute(table.select()).all()
            except Exception:                                    # table lives in the other database
                continue
            dump = " ".join(str(v) for row in rows for v in row)
            for number in numbers:
                assert number not in dump, f"{number} found in {table.name}"


# ---------------------------------------------------------------- no images
def test_a_document_image_field_is_refused(client, letters):
    resp = client.post("/enrolment/apply", json={**TAYLOR, "document_image": "iVBORw0KGgoAAAANSUhEUg=="})
    assert resp.status_code == 400 and checks() == [] and letters == []


def test_a_document_upload_is_refused(client, letters):
    resp = client.post("/enrolment/apply", content_type="multipart/form-data",
                       data={**TAYLOR, "document": (io.BytesIO(b"\x89PNG\r\n\x1a\n fake scan"), "licence.png")})
    assert resp.status_code == 400 and checks() == []


def test_no_route_in_the_app_takes_a_document_upload(app):
    routes = [r.rule for r in app.url_map.iter_rules()]
    assert not any(word in r for r in routes for word in ("upload", "scan", "image", "photo"))


# ---------------------------------------------------------------- de-identified copy for analysis
def test_the_analysis_copy_has_no_names_addresses_or_documents(client, letters, monkeypatch):
    client.post("/enrolment/apply", json=TAYLOR)
    act_as(monkeypatch, AUDITOR)
    body = client.get("/enrolment/analysis").get_json()
    assert body["count"] == 2
    for row in body["rows"]:
        assert set(row) == {"pseudonym", "division", "state", "age_band", "status"}
    dump = str(body)
    for value in PERSONAL + ("elector-alex", taylor().id, taylor().doc_hash):
        assert value not in dump


def test_pseudonyms_are_distinct_stable_and_not_the_real_id(client, letters, monkeypatch):
    client.post("/enrolment/apply", json=TAYLOR)
    first = r09.deidentified_roll(AUDITOR)
    second = r09.deidentified_roll(AUDITOR)
    names = [r["pseudonym"] for r in first]
    assert len(set(names)) == 2 and names == [r["pseudonym"] for r in second]
    assert "elector-alex" not in names


def test_ages_become_bands(app):
    from datetime import date
    today = date(2026, 10, 27)
    assert r09.age_band(date(1990, 4, 12), today) == "35-44"
    assert r09.age_band(date(2009, 1, 1), today) == "16-17"
    assert r09.age_band(date(2008, 10, 27), today) == "18-24"
    assert r09.age_band(date(1950, 1, 1), today) == "65+"


def test_taking_a_copy_is_audited(app):
    r09.deidentified_roll(AUDITOR)
    event = db.session.execute(text("SELECT event, actor_id, details FROM audit_log ORDER BY id DESC")).first()
    assert event[0] == "ENROLMENT_ANALYSIS_COPY" and event[1] == AUDITOR["id"] and '"rows":1' in event[2]


@pytest.mark.parametrize("user", [OFFICER, VOTER, None])
def test_only_auditors_get_a_copy(app, user):
    assert r09.deidentified_roll(user) is None


def test_the_analysis_route_needs_sign_in(app, client):
    app.config.update(LOGIN_ENFORCE=True)
    assert client.get("/enrolment/analysis").status_code == 401
