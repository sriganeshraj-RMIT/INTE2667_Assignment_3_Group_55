"""R7 - Two independent counts: the result is saved only when both programs agree."""
import random
from datetime import timedelta

import pytest

from app import create_app
from app.auth.r14_models import AccessGrant, now
from app.ballot import r05_crypto
from app.ballot.r05_models import ElectionKey
from app.election import r07_count as r07
from app.election import r07_count_a, r07_count_b
from app.election.r07_models import CountResult
from app.election.r19_models import Exclusion
from app.extensions import db
from tests.setd_helpers import (USERS, add_election, create_ballot_tables, create_base_tables, login_as,
                                store_sealed)

MODULE = "app.election.r07_count"
IDS = ["c1", "c2", "c3"]
# 4 voters: c1>c2>c3   3 voters: c2>c3>c1   2 voters: c3>c2>c1   (nobody has more than half at first)
PLAIN = [{"c1": 1, "c2": 2, "c3": 3}] * 4 + [{"c2": 1, "c3": 2, "c1": 3}] * 3 + [{"c3": 1, "c2": 2, "c1": 3}] * 2


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        create_base_tables()
        create_ballot_tables()
        add_election("e1", "CLOSED", tuple(IDS))
        yield app
        db.session.remove()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


@pytest.fixture
def ballots(monkeypatch):
    """Replace the (not yet connected) ballot source with a list the test controls."""
    box = {"list": list(PLAIN)}
    monkeypatch.setattr(f"{MODULE}.get_decrypted_ballots", lambda election_id, shares=None: box["list"])
    return box


def give_access(who="counter", scope="counting"):
    db.session.add(AccessGrant(requester_id=USERS[who]["id"], ticket_no="INC-1", reason="Count", scope=scope,
                               status="APPROVED", approver_id="user-admin-1", approved_at=now(),
                               expires_at=now() + timedelta(hours=4)))
    db.session.commit()


# ---------------------------------------------------------- the two programs
def test_known_election_has_the_expected_answer():
    orders = [["c1", "c2", "c3"]] * 4 + [["c2", "c3", "c1"]] * 3 + [["c3", "c2", "c1"]] * 2
    for program in (r07_count_a, r07_count_b):
        result = program.count(orders, IDS)
        assert result["winner"] == "c2"
        assert result["rounds"][0]["eliminated"] == "c3"                 # c3 had the fewest votes
        assert result["rounds"][1]["tallies"] == {"c1": 4, "c2": 5}


def test_the_two_programs_agree_on_many_random_elections():
    rng = random.Random(7)
    cands = ["a", "b", "c", "d", "e"]
    for _ in range(400):
        orders = [rng.sample(cands, rng.randint(0, 5)) for _ in range(rng.randint(0, 40))]
        excluded = rng.sample(cands, rng.randint(0, 3))
        assert r07_count_a.count(orders, cands, excluded) == r07_count_b.count(orders, cands, excluded)


def test_ties_are_broken_the_same_way_every_time():
    orders = [["a"], ["b"]]                                      # a and b tied: the lowest ID goes out first
    assert r07_count_a.count(orders, ["a", "b"])["winner"] == "b"
    assert r07_count_b.count(orders, ["a", "b"])["winner"] == "b"


def test_empty_election_has_no_winner():
    assert r07_count_a.count([], IDS)["winner"] is None and r07_count_b.count([], IDS)["winner"] is None


# ------------------------------------------------------- the count itself
def test_matching_counts_are_saved_and_logged(app, ballots, audit_log):
    row, payload = r07.run_count(USERS["counter"], "e1")
    assert payload["winner"] == "c2" and payload["ballots_counted"] == 9 and payload["ballots_informal"] == 0
    assert db.session.get(CountResult, row.id).payload_json == r07.canonical(payload).decode()
    assert audit_log[-1][0] == "ELECTION_COUNT_COMPLETED"


def test_if_the_programs_disagree_nothing_is_saved(app, ballots, audit_log, monkeypatch):
    monkeypatch.setattr(r07_count_b, "count", lambda *a, **k: {"winner": "c1", "rounds": []})
    with pytest.raises(r07.CountError) as e:
        r07.run_count(USERS["counter"], "e1")
    assert e.value.code == "COUNT_MISMATCH" and e.value.status == 409
    assert db.session.query(CountResult).count() == 0
    assert audit_log[-1][0] == "ELECTION_COUNT_MISMATCH"


def test_informal_ballots_are_set_aside_not_counted(app, ballots):
    ballots["list"] = PLAIN + [{"c1": 1, "c2": 1, "c3": 2},          # repeated number
                               {"c1": 1, "c2": 2},                      # missing candidate
                               {"c1": 1, "c2": 3, "c3": 4},             # gap in numbers
                               {"c1": True, "c2": 2, "c3": 3},          # not a real number
                               "not even a ballot"]
    _, payload = r07.run_count(USERS["counter"], "e1")
    assert payload["ballots_counted"] == 9 and payload["ballots_informal"] == 5


def test_only_approved_exclusions_change_the_count(app, ballots):
    db.session.add(Exclusion(election_id="e1", candidate_id="c2", reason="Order", status="PENDING", proposed_by="d1"))
    db.session.commit()
    _, payload = r07.run_count(USERS["counter"], "e1")
    assert payload["excluded"] == [] and payload["winner"] == "c2"          # a proposal alone changes nothing
    db.session.query(Exclusion).update({"status": "APPROVED", "approved_by": "d2"})
    db.session.commit()
    _, payload = r07.run_count(USERS["counter"], "e1")
    assert payload["excluded"] == ["c2"] and payload["winner"] != "c2"
    assert "c2" not in payload["rounds"][0]["tallies"]


def test_count_waits_until_the_polls_are_closed(app, ballots):
    add_election("e2", "OPEN", ("x1", "x2"))
    with pytest.raises(r07.CountError) as e:
        r07.run_count(USERS["counter"], "e2")
    assert e.value.code == "POLLS_NOT_CLOSED" and e.value.status == 409


def test_unknown_election_is_not_found(app, ballots):
    with pytest.raises(r07.CountError) as e:
        r07.run_count(USERS["counter"], "nope")
    assert e.value.status == 404


@pytest.mark.parametrize("who", ["voter", "delegate1", "custodian", "auditor"])
def test_only_counting_officers_and_admins_can_count(app, ballots, who):
    with pytest.raises(r07.CountError) as e:
        r07.run_count(USERS[who], "e1")
    assert e.value.status == 403


def test_an_admin_can_count_too(app, ballots):
    _, payload = r07.run_count(USERS["admin"], "e1")
    assert payload["winner"] == "c2"


def test_a_refused_count_is_logged(app, ballots, audit_log):
    with pytest.raises(r07.CountError):
        r07.run_count(USERS["voter"], "e1")
    event, actor, details = audit_log[-1]
    assert event == "ELECTION_COUNT_REFUSED" and actor == USERS["voter"]["id"] and details["role"] == "voter"


def test_an_admin_needs_live_access_to_count_over_http(app, ballots, monkeypatch):
    login_as(monkeypatch, "admin", MODULE, "app.auth.r14_elevation")
    client = app.test_client()
    assert client.post("/election/e1/count").get_json()["error"] == "ELEVATION_REQUIRED"     # an admin alone: refused
    give_access("admin", "counting")
    assert client.post("/election/e1/count").status_code == 200


def test_without_an_election_key_it_says_so(app):
    with pytest.raises(r07.CountError) as e:
        r07.run_count(USERS["counter"], "e1", ["1-a", "2-b", "3-c"])
    assert e.value.code == "NO_ELECTION_KEY" and e.value.status == 409


# ------------------------------------------------------------------- HTTP
def test_route_is_refused_without_r14_access(app, ballots, monkeypatch):
    login_as(monkeypatch, "counter", MODULE, "app.auth.r14_elevation")
    resp = app.test_client().post("/election/e1/count")
    assert resp.status_code == 403 and resp.get_json()["error"] == "ELEVATION_REQUIRED"
    assert db.session.query(CountResult).count() == 0


def test_route_counts_with_r14_access(app, ballots, monkeypatch):
    login_as(monkeypatch, "counter", MODULE, "app.auth.r14_elevation")
    give_access("counter", "counting")
    resp = app.test_client().post("/election/e1/count")
    assert resp.status_code == 200 and resp.get_json()["result"]["winner"] == "c2"


def test_route_access_for_the_results_scope_is_not_enough(app, ballots, monkeypatch):
    login_as(monkeypatch, "counter", MODULE, "app.auth.r14_elevation")
    give_access("counter", "results")
    assert app.test_client().post("/election/e1/count").status_code == 403


# ====================================== the whole chain with the REAL R5 (sealed ballots, 3 of 5 shares)
@pytest.fixture(scope="module")
def material():
    return r05_crypto.make_election_key()


@pytest.fixture
def sealed_box(app, material):
    """Election e1 has a key, and the box holds 9 really sealed ballots (the PLAIN ones) plus a damaged one."""
    public_pem, locked, shares = material
    db.session.add(ElectionKey(election_id="e1", public_key_pem=public_pem, locked_private_key=locked,
                               threshold=3, share_count=5, created_by="user-custodian-1"))
    db.session.commit()
    for ballot in PLAIN:
        store_sealed("e1", r05_crypto.seal_ballot(public_pem, "e1", ballot))
    store_sealed("e1", "a damaged ballot")
    return shares


def test_end_to_end_three_shares_open_the_box_and_the_count_runs(sealed_box, audit_log):
    row, payload = r07.run_count(USERS["counter"], "e1", sealed_box[:3])
    assert payload["winner"] == "c2" and payload["ballots_counted"] == 9 and payload["ballots_informal"] == 1
    assert audit_log[-1][0] == "ELECTION_COUNT_COMPLETED"


def test_end_to_end_any_three_shares_give_the_same_result(sealed_box):
    first = r07.run_count(USERS["counter"], "e1", sealed_box[:3])[1]
    second = r07.run_count(USERS["counter"], "e1", [sealed_box[4], sealed_box[1], sealed_box[2]])[1]
    assert first["rounds"] == second["rounds"] and first["winner"] == second["winner"]


def test_end_to_end_two_shares_leave_the_box_shut(sealed_box, audit_log):
    with pytest.raises(r07.CountError) as e:
        r07.run_count(USERS["counter"], "e1", sealed_box[:2])
    assert e.value.code == "BAD_SHARES" and e.value.status == 403
    assert db.session.query(CountResult).count() == 0
    assert audit_log[-1][0] == "ELECTION_COUNT_BAD_SHARES"


def test_end_to_end_no_shares_at_all_leave_the_box_shut(sealed_box):
    with pytest.raises(r07.CountError) as e:
        r07.run_count(USERS["counter"], "e1")
    assert e.value.code == "BAD_SHARES"


def test_end_to_end_over_http_with_the_shares_in_the_request(app, sealed_box, monkeypatch):
    login_as(monkeypatch, "counter", MODULE, "app.auth.r14_elevation")
    give_access("counter", "counting")
    client = app.test_client()
    assert client.post("/election/e1/count", json={"shares": sealed_box[:2]}).get_json()["error"] == "BAD_SHARES"
    assert client.post("/election/e1/count", json={}).get_json()["error"] == "BAD_SHARES"
    resp = client.post("/election/e1/count", json={"shares": sealed_box[:3]})
    assert resp.status_code == 200 and resp.get_json()["result"]["winner"] == "c2"


@pytest.mark.parametrize("bad", ["not a list", 5, [1, 2, 3], ["x" * 500], ["1-a"] * 11])
def test_badly_shaped_shares_in_the_request_are_refused(app, ballots, monkeypatch, bad):
    login_as(monkeypatch, "counter", MODULE, "app.auth.r14_elevation")
    give_access("counter", "counting")
    resp = app.test_client().post("/election/e1/count", json={"shares": bad})
    assert resp.status_code == 400 and resp.get_json()["error"] == "VALIDATION_FAILED"
