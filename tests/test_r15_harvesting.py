"""R15 - No harvesting of the voter list.

Redis is replaced by a small in-memory fake (FakeRedis below) so the tests run without Docker and
without adding a package. Acting as a user works like the other teams' tests: current_user is replaced
in the module under test.
"""
import uuid
from datetime import date

import pytest

from app import create_app
from app.enrolment import r15_harvest as r15
from app.enrolment.models import Elector
from app.extensions import db

MODULE = "app.enrolment.r15_harvest"

OFFICER = {"id": "u-officer-1", "role": "officer", "division": "Melbourne", "state": "VIC"}
OFFICER_NO_DIVISION = {"id": "u-officer-2", "role": "officer", "division": None, "state": None}
VOTER = {"id": "u-voter-1", "role": "voter", "division": "Melbourne", "state": "VIC"}
ADMIN = {"id": "u-admin-1", "role": "admin", "division": None, "state": None}

ALEX = {"given_name": "Alex", "family_name": "Citizen", "dob": "1990-04-12", "postcode": "3000"}
NOBODY = {"given_name": "Nobody", "family_name": "Unknown", "dob": "1999-01-01", "postcode": "3000"}


class FakeRedis:
    """Just the three Redis commands R15 uses."""

    def __init__(self):
        self.data, self.ttl = {}, {}

    def incrby(self, key, amount):
        self.data[key] = self.data.get(key, 0) + amount
        return self.data[key]

    def expire(self, key, seconds):
        self.ttl[key] = seconds

    def get(self, key):
        value = self.data.get(key)
        return None if value is None else str(value).encode()      # real Redis returns bytes


def add_elector(given, family, dob="1990-04-12", postcode="3000", suburb="Melbourne",
                division="Melbourne", email=None, status="ENROLLED"):
    db.session.add(Elector(id=str(uuid.uuid4()), given_name=given, family_name=family,
                           dob=date.fromisoformat(dob), address_line="1 Test St", suburb=suburb,
                           postcode=postcode, state="VIC", division=division, email=email, status=status))


@pytest.fixture
def app():
    app = create_app()
    app.config.update(TESTING=True, R15_MIN_RESPONSE_SECONDS=0)
    with app.app_context():
        db.create_all()
        add_elector("Alex", "Citizen", email="alex@evp.test")
        add_elector("Riley", "Patel", postcode="3181", suburb="Prahran", division="Macnamara",
                    email="riley@evp.test")
        for i in range(60):                                      # enough rows to test the caps
            add_elector(f"Person{chr(65 + i % 26)}{i}", "Nguyen", dob="2000-01-01")
        db.session.commit()
        yield app
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(f"{MODULE}.get_redis", lambda: fake)
    return fake


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


@pytest.fixture
def emails(monkeypatch):
    sent = []
    monkeypatch.setattr(f"{MODULE}._deliver", lambda to, division: sent.append((to, division)))
    return sent


def act_as(monkeypatch, user):
    monkeypatch.setattr(f"{MODULE}.current_user", lambda: user)


def check(client, details, ip="10.0.0.1"):
    return client.post("/enrolment/check", json=details, environ_base={"REMOTE_ADDR": ip})


def search(**filters):
    return r15.search_voters(OFFICER, {"limit": 50, **filters})


# ---------------------------------------------------------------- 1. enrolment check gives nothing away
def test_reply_is_identical_whether_enrolled_or_not(client, redis, audit_log, emails):
    enrolled = check(client, ALEX, ip="10.0.0.1")
    not_enrolled = check(client, NOBODY, ip="10.0.0.2")
    assert enrolled.status_code == not_enrolled.status_code == 200
    assert enrolled.get_data() == not_enrolled.get_data()           # byte-for-byte the same


def test_the_real_answer_only_goes_to_the_email_on_the_roll(client, redis, audit_log, emails):
    check(client, ALEX)
    check(client, NOBODY, ip="10.0.0.2")
    assert emails == [("alex@evp.test", "Melbourne")]               # nothing is sent for a non-match


def test_the_audit_log_does_not_record_whether_someone_is_enrolled(client, redis, audit_log, emails):
    check(client, ALEX)
    check(client, NOBODY, ip="10.0.0.2")
    assert [c[2] for c in audit_log] == [{}, {}]


def test_lookups_from_one_ip_are_limited(client, redis, audit_log, emails):
    for i in range(r15.LOOKUPS_PER_IP):
        assert check(client, {**NOBODY, "given_name": f"Guess{chr(65 + i)}"}).status_code == 200
    resp = check(client, {**NOBODY, "given_name": "Another"})
    assert resp.status_code == 429 and resp.get_json()["error"] == "RATE_LIMITED"
    assert audit_log[-1] == ("ENROLMENT_LOOKUP_RATE_LIMITED", "anonymous", {"limit": "ip"})


def test_one_person_probed_from_many_ips_is_limited(client, redis, audit_log, emails):
    for i in range(r15.LOOKUPS_PER_PERSON):
        assert check(client, ALEX, ip=f"10.0.1.{i}").status_code == 200
    resp = check(client, ALEX, ip="10.0.1.99")
    assert resp.status_code == 429 and resp.get_json()["error"] == "RATE_LIMITED"
    assert audit_log[-1][2] == {"limit": "person"}


def test_rate_limit_keys_hold_no_personal_details(client, redis, audit_log, emails):
    check(client, ALEX, ip="203.0.113.7")
    keys = " ".join(redis.data)
    for secret in ("Alex", "alex", "Citizen", "citizen", "1990-04-12", "203.0.113.7"):
        assert secret not in keys
    assert set(redis.ttl.values()) == {r15.IP_WINDOW_SECONDS, r15.PERSON_WINDOW_SECONDS}


@pytest.mark.parametrize("bad", [
    {**ALEX, "family_name": "' OR 1=1 --"},                         # injection attempt
    {**ALEX, "dob": "12/04/1990"},
    {**ALEX, "postcode": "30000"},
    {**ALEX, "extra": "field"},
])
def test_bad_input_is_refused(client, redis, audit_log, emails, bad):
    assert check(client, bad).status_code == 400
    assert redis.data == {}                                          # refused before any lookup


# ---------------------------------------------------------------- 2. staff search: limited and watched
def test_officer_finds_voters_in_their_division_without_dob_or_email(app, redis, audit_log):
    results = search(family_name="Citizen", postcode="3000")
    assert [r["given_name"] for r in results] == ["Alex"]
    assert "dob" not in results[0] and "email" not in results[0]


@pytest.mark.parametrize("user", [VOTER, ADMIN, None])
def test_only_officers_can_search(app, redis, audit_log, user):
    with pytest.raises(r15.HarvestError) as e:
        r15.search_voters(user, {"family_name": "Citizen", "postcode": "3000", "limit": 20})
    assert e.value.status == 403
    assert audit_log[-1][0] == "VOTERLIST_SEARCH_REFUSED"


def test_an_officer_without_a_division_is_refused(app, redis, audit_log):
    with pytest.raises(r15.HarvestError) as e:
        r15.search_voters(OFFICER_NO_DIVISION, {"family_name": "Citizen", "postcode": "3000", "limit": 20})
    assert e.value.status == 403


def test_voters_in_another_division_are_never_returned(app, redis, audit_log):
    assert search(family_name="Patel", postcode="3181") == []          # Riley is in Macnamara


def test_every_search_is_audited_with_counts_not_values(app, redis, audit_log):
    search(family_name="Citizen", postcode="3000")
    event, actor, details = audit_log[-1]
    assert event == "VOTERLIST_SEARCH" and actor == OFFICER["id"]
    assert details == {"fields": ["family_name", "postcode"], "results": 1}


# ---------------------------------------------------------------- 3. no bulk download
def test_a_family_name_alone_is_too_broad(app, redis, audit_log):
    with pytest.raises(r15.HarvestError) as e:
        r15.search_voters(OFFICER, {"family_name": "Nguyen", "limit": 20})
    assert e.value.code == "FILTER_TOO_BROAD"


def test_results_are_capped_at_50(app, redis, audit_log):
    assert len(search(family_name="Nguyen", postcode="3000")) == 50       # 60 exist


def test_wildcards_do_not_widen_the_search(app, redis, audit_log):
    assert search(family_name="Ngu%", postcode="3000") == []          # exact match only


@pytest.mark.parametrize("body", [
    {"family_name": "Nguyen", "postcode": "3000", "limit": 51},       # over the cap
    {"family_name": "Ng", "postcode": "3000"},                        # name too short
    {"family_name": "Nguyen", "postcode": "3000", "offset": 50},      # no paging
])
def test_route_refuses_requests_that_could_pull_more_data(client, redis, audit_log, monkeypatch, body):
    act_as(monkeypatch, OFFICER)
    assert client.post("/enrolment/voters/search", json=body).status_code == 400


def test_there_is_no_route_that_lists_or_exports_the_roll(client):
    for path in ("/enrolment/voters", "/enrolment/voters/export", "/enrolment/export"):
        assert client.get(path).status_code == 404


def test_search_route_works_for_an_officer(client, redis, audit_log, monkeypatch):
    act_as(monkeypatch, OFFICER)
    resp = client.post("/enrolment/voters/search", json={"family_name": "Nguyen", "postcode": "3000", "limit": 10})
    body = resp.get_json()
    assert resp.status_code == 200 and body["count"] == 10 and body["truncated"] is True


# ---------------------------------------------------------------- 4. more than 1,000 records a minute
def test_reading_more_than_1000_records_a_minute_raises_one_alert_and_blocks(app, redis, audit_log, monkeypatch):
    monkeypatch.setattr(f"{MODULE}._now", lambda: 6000.0)          # stay inside one minute
    for _ in range(20):                                              # 20 x 50 = exactly 1,000: allowed
        assert len(search(family_name="Nguyen", postcode="3000")) == 50
    assert not any(c[0] == "VOTERLIST_BULK_READ_ALERT" for c in audit_log)

    with pytest.raises(r15.HarvestError) as e:                       # the 1,001st record onwards
        search(family_name="Nguyen", postcode="3000")
    assert e.value.code == "BULK_READ_BLOCKED" and e.value.status == 429
    alerts = [c for c in audit_log if c[0] == "VOTERLIST_BULK_READ_ALERT"]
    assert alerts == [("VOTERLIST_BULK_READ_ALERT", OFFICER["id"],
                       {"records_this_minute": 1050, "limit": 1000})]

    with pytest.raises(r15.HarvestError):                            # still blocked, no second alert
        search(family_name="Citizen", postcode="3000")
    assert len([c for c in audit_log if c[0] == "VOTERLIST_BULK_READ_ALERT"]) == 1

    monkeypatch.setattr(f"{MODULE}._now", lambda: 6060.0)          # next minute: allowed again
    assert len(search(family_name="Citizen", postcode="3000")) == 1


def test_the_minute_counter_is_per_account(app, redis, audit_log, monkeypatch):
    monkeypatch.setattr(f"{MODULE}._now", lambda: 6000.0)
    for _ in range(20):
        search(family_name="Nguyen", postcode="3000")
    with pytest.raises(r15.HarvestError):                            # this officer is now blocked...
        search(family_name="Nguyen", postcode="3000")
    other = {**OFFICER, "id": "u-officer-3"}                         # ...but a colleague is not
    assert len(r15.search_voters(other, {"family_name": "Citizen", "postcode": "3000", "limit": 20})) == 1
