"""R5 - Sealed ballots: locked on the voter's device, opened only with 3 of the 5 shares."""
import itertools

import pytest

from app import create_app
from app.ballot import r05_crypto as crypto
from app.ballot import r05_keys as keys
from app.ballot import r05_open as opening
from app.ballot.r05_models import ElectionKey
from app.extensions import db
from tests.setd_helpers import (USERS, add_election, create_ballot_tables, create_base_tables, login_as,
                                store_sealed)

MODULE = "app.ballot.r05_keys"
BALLOT = {"c1": 1, "c2": 2, "c3": 3}


@pytest.fixture(scope="module")
def material():
    """One real key ceremony for the whole file (making an RSA key takes a moment)."""
    return crypto.make_election_key()


@pytest.fixture(scope="module")
def other_material():
    return crypto.make_election_key()


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        db.create_all()
        create_base_tables()
        create_ballot_tables()
        add_election("e1", "DRAFT", ("c1", "c2", "c3"))
        yield app
        db.session.remove()


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


@pytest.fixture
def installed(app, material):
    """The ceremony's result for election e1, as the database would hold it."""
    public_pem, locked, shares = material
    db.session.add(ElectionKey(election_id="e1", public_key_pem=public_pem, locked_private_key=locked,
                               threshold=3, share_count=5, created_by="user-custodian-1"))
    db.session.commit()
    return public_pem, shares


# ------------------------------------------------------------- locking a ballot
def test_a_sealed_ballot_opens_with_the_private_key(material):
    public_pem, locked, shares = material
    sealed = crypto.seal_ballot(public_pem, "e1", BALLOT)
    private_key = crypto.unlock_private_key(locked, shares[:3])
    assert crypto.open_ballot(private_key, "e1", sealed) == BALLOT


def test_a_sealed_ballot_does_not_show_the_vote(material):
    sealed = crypto.seal_ballot(material[0], "e1", {"candidate-one": 1, "candidate-two": 2})
    assert "candidate-one" not in sealed and "candidate-two" not in sealed


def test_the_same_ballot_sealed_twice_looks_different(material):
    assert crypto.seal_ballot(material[0], "e1", BALLOT) != crypto.seal_ballot(material[0], "e1", BALLOT)


def test_a_ballot_cannot_be_moved_to_another_election(material):
    public_pem, locked, shares = material
    sealed = crypto.seal_ballot(public_pem, "e1", BALLOT)
    private_key = crypto.unlock_private_key(locked, shares[:3])
    assert crypto.open_ballot(private_key, "e2", sealed) is None


def test_a_damaged_or_fake_ballot_comes_back_as_none(material):
    public_pem, locked, shares = material
    private_key = crypto.unlock_private_key(locked, shares[:3])
    sealed = crypto.seal_ballot(public_pem, "e1", BALLOT)
    damaged = sealed[:-12] + ("A" if sealed[-12] != "A" else "B") + sealed[-11:]
    odd = ["[" * 5000, '{"ek": "!!", "n": "", "c": ""}', '{"ek": null, "n": null, "c": null}', "5", "null"]
    for bad in [damaged, "not json", "{}", '{"ek": 1}', "[]", ""] + odd:        # none of these may crash the count
        assert crypto.open_ballot(private_key, "e1", bad) is None


# ------------------------------------------------------ the 3-of-5 key shares
def test_any_three_of_the_five_shares_open_the_box(material):
    _, locked, shares = material
    assert len(shares) == 5
    for three in itertools.combinations(shares, 3):
        assert crypto.unlock_private_key(locked, list(three))


def test_more_than_three_shares_also_work(material):
    _, locked, shares = material
    assert crypto.unlock_private_key(locked, shares[:4]) and crypto.unlock_private_key(locked, shares)


def test_two_shares_are_not_enough(material):
    _, locked, shares = material
    for two in itertools.combinations(shares, 2):
        with pytest.raises(crypto.BadShares):
            crypto.unlock_private_key(locked, list(two))


def test_one_share_repeated_is_not_enough(material):
    _, locked, shares = material
    with pytest.raises(crypto.BadShares):
        crypto.unlock_private_key(locked, [shares[0], shares[0], shares[0]])


def test_a_wrong_share_is_refused(material):
    _, locked, shares = material
    x, y = shares[2].split("-")
    wrong = f"{x}-{y[:-1]}{'0' if y[-1] != '0' else '1'}"
    with pytest.raises(crypto.BadShares):
        crypto.unlock_private_key(locked, [shares[0], shares[1], wrong])


def test_shares_from_another_election_are_refused(material, other_material):
    _, locked, _ = material
    with pytest.raises(crypto.BadShares):
        crypto.unlock_private_key(locked, other_material[2][:3])


@pytest.mark.parametrize("bad", [["hello", "1-zz", "2-1"], ["", "", ""], [None, 5, "x"], "1-ab", None, []])
def test_badly_typed_shares_are_refused(material, bad):
    with pytest.raises(crypto.BadShares):
        crypto.unlock_private_key(material[1], bad)


def test_the_stored_private_key_is_not_readable(material):
    import base64
    blob = base64.b64decode(material[1])
    assert b"PRIVATE KEY" not in blob and b"BEGIN" not in blob


def test_shares_are_not_the_secret_and_differ_from_each_other(material):
    shares = material[2]
    assert len(set(shares)) == 5 and all(crypto.SHARE_PATTERN.match(s) for s in shares)


# --------------------------------------------------------- the key ceremony
def test_a_custodian_runs_the_ceremony_and_gets_five_shares(app, audit_log):
    public_pem, shares = keys.run_ceremony(USERS["custodian"], "e1")
    row = db.session.get(ElectionKey, "e1")
    assert "BEGIN PUBLIC KEY" in public_pem and len(shares) == 5
    assert row.threshold == 3 and row.share_count == 5 and row.created_by == USERS["custodian"]["id"]
    assert crypto.unlock_private_key(row.locked_private_key, shares[1:4])          # the shares really open it


def test_the_shares_are_never_stored_or_logged(app, audit_log):
    _, shares = keys.run_ceremony(USERS["custodian"], "e1")
    row = db.session.get(ElectionKey, "e1")
    stored_text = " ".join(str(v) for v in (row.public_key_pem, row.locked_private_key, row.created_by))
    logged_text = str(audit_log)
    for share in shares:
        assert share not in stored_text and share not in logged_text
    assert audit_log[-1][0] == "BALLOT_KEY_CEREMONY_DONE"


@pytest.mark.parametrize("who", ["voter", "admin", "counter", "delegate1", "auditor"])
def test_only_a_custodian_can_run_the_ceremony_and_refusals_are_logged(app, audit_log, who):
    with pytest.raises(keys.CeremonyError) as e:
        keys.run_ceremony(USERS[who], "e1")
    assert e.value.status == 403 and db.session.get(ElectionKey, "e1") is None
    assert audit_log[-1][0] == "BALLOT_KEY_CEREMONY_REFUSED" and audit_log[-1][1] == USERS[who]["id"]


def test_nobody_signed_in_cannot_run_the_ceremony(app, audit_log):
    with pytest.raises(keys.CeremonyError):
        keys.run_ceremony(None, "e1")
    assert audit_log[-1][1] == "anonymous"


def test_the_ceremony_needs_a_real_election_that_is_not_open_yet(app):
    with pytest.raises(keys.CeremonyError) as e:
        keys.run_ceremony(USERS["custodian"], "nope")
    assert e.value.status == 404
    for status in ("OPEN", "CLOSED"):
        add_election(f"x-{status}", status, (f"{status}-a", f"{status}-b"))
        with pytest.raises(keys.CeremonyError) as e:
            keys.run_ceremony(USERS["custodian"], f"x-{status}")
        assert e.value.code == "ELECTION_ALREADY_OPEN"


def test_an_election_gets_only_one_key(app, installed):
    with pytest.raises(keys.CeremonyError) as e:
        keys.run_ceremony(USERS["custodian"], "e1")
    assert e.value.code == "KEY_EXISTS" and e.value.status == 409


# ------------------------------------------------------------- HTTP routes
def test_http_ceremony_returns_shares_once_and_is_not_cached(app, monkeypatch):
    login_as(monkeypatch, "custodian", MODULE)
    resp = app.test_client().post("/ballot/e1/ceremony")
    body = resp.get_json()
    assert resp.status_code == 200 and len(body["shares"]) == 5 and body["needed_to_open"] == 3
    assert resp.headers["Cache-Control"] == "no-store"
    assert app.test_client().post("/ballot/e1/ceremony").get_json()["error"] == "KEY_EXISTS"


def test_http_ceremony_refuses_other_roles(app, monkeypatch):
    login_as(monkeypatch, "voter", MODULE)
    resp = app.test_client().post("/ballot/e1/ceremony")
    assert resp.status_code == 403 and set(resp.get_json()) == {"error", "message"}


def test_the_public_key_is_public(app, installed, monkeypatch):
    login_as(monkeypatch, None, MODULE)
    body = app.test_client().get("/ballot/e1/public-key").get_json()
    assert "BEGIN PUBLIC KEY" in body["public_key_pem"] and "PRIVATE" not in str(body)


def test_no_public_key_before_the_ceremony(app):
    resp = app.test_client().get("/ballot/e1/public-key")
    assert resp.status_code == 404 and resp.get_json()["error"] == "NOT_FOUND"


# ------------------------------------------------------ opening the ballot box
def test_the_box_opens_with_three_shares(app, installed):
    public_pem, shares = installed
    for ballot in ({"c1": 1, "c2": 2, "c3": 3}, {"c3": 1, "c2": 2, "c1": 3}):
        store_sealed("e1", crypto.seal_ballot(public_pem, "e1", ballot))
    opened = opening.open_ballots("e1", shares[:3])
    assert len(opened) == 2 and {"c1": 1, "c2": 2, "c3": 3} in opened and {"c3": 1, "c2": 2, "c1": 3} in opened


def test_the_box_stays_shut_with_two_shares(app, installed):
    public_pem, shares = installed
    store_sealed("e1", crypto.seal_ballot(public_pem, "e1", BALLOT))
    with pytest.raises(opening.BadShares):
        opening.open_ballots("e1", shares[:2])


def test_only_this_elections_ballots_are_opened(app, installed):
    public_pem, shares = installed
    store_sealed("e1", crypto.seal_ballot(public_pem, "e1", BALLOT))
    store_sealed("other", crypto.seal_ballot(public_pem, "other", {"z": 1}))
    assert opening.open_ballots("e1", shares[:3]) == [BALLOT]


def test_a_damaged_ballot_in_the_box_comes_back_as_none(app, installed):
    public_pem, shares = installed
    store_sealed("e1", crypto.seal_ballot(public_pem, "e1", BALLOT))
    store_sealed("e1", "this is not a sealed ballot")
    opened = opening.open_ballots("e1", shares[:3])
    assert BALLOT in opened and None in opened and len(opened) == 2


def test_a_ballot_that_is_not_even_text_cannot_stop_the_count(app, installed):
    public_pem, shares = installed
    store_sealed("e1", crypto.seal_ballot(public_pem, "e1", BALLOT))
    store_sealed("e1", b"\xff\xfe\x00\x80")
    assert sorted(opening.open_ballots("e1", shares[:3]), key=lambda b: b is None) == [BALLOT, None]


def test_ballots_come_out_in_id_order_not_in_the_order_they_arrived(app, installed):
    public_pem, shares = installed
    store_sealed("e1", crypto.seal_ballot(public_pem, "e1", {"first": 1}), ballot_id="b" * 32)    # arrived first
    store_sealed("e1", crypto.seal_ballot(public_pem, "e1", {"second": 1}), ballot_id="a" * 32)   # arrived second
    assert opening.open_ballots("e1", shares[:3]) == [{"second": 1}, {"first": 1}]


def test_opening_without_a_key_says_so(app):
    with pytest.raises(opening.NoElectionKey):
        opening.open_ballots("e1", ["1-a", "2-b", "3-c"])
