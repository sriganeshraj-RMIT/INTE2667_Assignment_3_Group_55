"""R4 - No clues in the ballot box: random ids, shuffled batch writes, no times / IPs / voter, clean logs."""
import hashlib
import inspect
import logging
import re
from pathlib import Path

import pytest
from sqlalchemy import text

from app import create_app
from app.ballot import r04_ballot_box as box
from app.election.r10_lock import ElectionError
from app.extensions import db
from tests.setd_helpers import add_election, create_ballot_tables, create_base_tables

MODULE = "app.ballot.r04_ballot_box"
BATCH = 3                                     # small batches keep the tests short


class FakeRedis:
    """Just enough of Redis for the ballot buffer: rpush, lrange, delete and a pipeline."""

    def __init__(self):
        self.lists = {}

    def rpush(self, key, *values):
        self.lists.setdefault(key, []).extend(v.encode() if isinstance(v, str) else v for v in values)
        return len(self.lists[key])

    def lrange(self, key, start, end):
        return list(self.lists.get(key, []))            # the code only ever asks for the whole list

    def delete(self, key):
        return 1 if self.lists.pop(key, None) is not None else 0

    def pipeline(self, transaction=True):
        return FakePipeline(self)


class FakePipeline:
    def __init__(self, redis):
        self.redis, self.calls = redis, []

    def lrange(self, *args):
        self.calls.append(("lrange", args))

    def delete(self, *args):
        self.calls.append(("delete", args))

    def execute(self):
        return [getattr(self.redis, name)(*args) for name, args in self.calls]


@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["BALLOT_BATCH_SIZE"] = BATCH
    with app.app_context():
        db.create_all()
        create_base_tables()
        create_ballot_tables()
        add_election("e1", "OPEN", ("c1", "c2"))
        add_election("e2", "OPEN", ("c3", "c4"))
        db.session.execute(text("UPDATE elections SET definition_fp = 'fp-' || id"))
        db.session.commit()
        yield app
        db.session.remove()


@pytest.fixture
def redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(f"{MODULE}.get_redis", lambda: fake)
    return fake


@pytest.fixture
def polls(monkeypatch):
    """R10's polls-open check is tested in test_r10_lock.py; here it just says 'open'."""
    monkeypatch.setattr(f"{MODULE}.require_polls_open", lambda election_id: None)


@pytest.fixture
def audit_log(monkeypatch):
    calls = []
    monkeypatch.setattr(f"{MODULE}.audit", lambda event, actor_id, details: calls.append((event, actor_id, details)))
    return calls


def stored(election_id="e1"):
    """The ballots table, in the order the rows were physically written (SQLite rowid)."""
    with db.engines["ballot"].connect() as c:
        return c.execute(text("SELECT id, ciphertext, ballot_hash, definition_fp, batch_id, chain_prev, chain_head "
                              "FROM ballots WHERE election_id = :eid ORDER BY rowid"),
                         {"eid": election_id}).mappings().all()


def sealed(n):
    return f'{{"ek": "key-{n}", "n": "nonce-{n}", "c": "sealed-ballot-{n}"}}'


# ----------------------------------------------------------- held back, then written as a batch
def test_ballots_are_held_back_until_a_batch_is_full(app, redis, polls, audit_log):
    box.store_ballot("e1", sealed(1))
    box.store_ballot("e1", sealed(2))
    assert stored() == []                                       # nothing in the box yet...
    assert len(redis.lists["ballot_pending:e1"]) == 2           # ...they are waiting
    assert audit_log == []                                      # and nothing is logged per ballot


def test_a_full_batch_is_written_together_with_one_batch_id(app, redis, polls, audit_log):
    for n in range(BATCH):
        box.store_ballot("e1", sealed(n))
    rows = stored()
    assert len(rows) == BATCH
    assert len({r["batch_id"] for r in rows}) == 1
    assert sorted(bytes(r["ciphertext"]).decode() for r in rows) == sorted(sealed(n) for n in range(BATCH))
    assert all(r["definition_fp"] == "fp-e1" for r in rows)
    assert "ballot_pending:e1" not in redis.lists              # the waiting list is emptied


def test_each_batch_gets_a_new_batch_id(app, redis, polls, audit_log):
    for n in range(BATCH * 2):
        box.store_ballot("e1", sealed(n))
    assert len({r["batch_id"] for r in stored()}) == 2


# ------------------------------------------------------------------- random ids, shuffled order
def test_ballot_ids_are_random_and_not_sequential(app, redis, polls, audit_log):
    for n in range(BATCH * 4):
        box.store_ballot("e1", sealed(n))
    ids = [r["id"] for r in stored()]
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    assert len(set(ids)) == len(ids)
    assert not all(i.isdigit() for i in ids)
    assert ids != sorted(ids)                                    # written order is not id order


def test_the_batch_is_shuffled_before_it_is_written(app, redis, polls, audit_log, monkeypatch):
    seen = []

    def spy_shuffle(items):
        seen.append(list(items))
        items.reverse()                                          # a known "shuffle" so the test is not random

    monkeypatch.setattr(box._shuffler, "shuffle", spy_shuffle)
    for n in range(BATCH):
        box.store_ballot("e1", sealed(n))
    assert seen == [[sealed(0), sealed(1), sealed(2)]]          # the arrival order went into the shuffle...
    written = [bytes(r["ciphertext"]).decode() for r in stored()]
    assert written == [sealed(2), sealed(1), sealed(0)]          # ...and is not the order written


def test_the_shuffle_uses_the_operating_system_random_source():
    import secrets
    assert isinstance(box._shuffler, secrets.SystemRandom)       # not the predictable `random` module


# --------------------------------------------------------------------- no time, IP or voter
def test_store_ballot_only_accepts_the_election_and_the_sealed_ballot():
    assert list(inspect.signature(box.store_ballot).parameters) == ["election_id", "sealed"]


def test_the_ballots_table_has_no_time_ip_or_voter_column():
    schema = (Path(__file__).resolve().parent.parent / "db" / "init" / "02_ballot.sql").read_text()
    table = schema.split("CREATE TABLE ballots", 1)[1].split(");", 1)[0]
    columns = [line.strip().split()[0].lower() for line in table.splitlines()[1:] if line.strip()]
    assert columns, "could not read the ballots table"
    forbidden = {"time", "timestamp", "ts", "date", "created", "ip", "addr", "address", "voter", "elector",
                 "user", "account", "email", "session"}
    for column in columns:
        assert not forbidden & set(column.split("_")), column       # whole words, so "ciphertext" is fine


def test_a_stored_row_holds_only_the_sealed_ballot_and_box_data(app, redis, polls, audit_log):
    for n in range(BATCH):
        box.store_ballot("e1", sealed(n))
    for row in stored():
        assert set(row.keys()) == {"id", "ciphertext", "ballot_hash", "definition_fp", "batch_id",
                                   "chain_prev", "chain_head"}


# ------------------------------------------------------------------------------- clean logs
def test_one_audit_entry_per_batch_with_no_ballot_details(app, redis, polls, audit_log):
    hashes = [box.store_ballot("e1", sealed(n)) for n in range(BATCH)]
    assert len(audit_log) == 1
    event, actor, details = audit_log[0]
    assert event == "BALLOT_BATCH_STORED" and actor == "system"
    assert details == {"election_id": "e1", "count": BATCH}
    logged = str(audit_log)
    for row in stored():
        assert row["id"] not in logged and row["batch_id"] not in logged
    for n, h in enumerate(hashes):
        assert sealed(n) not in logged and h not in logged


def test_nothing_about_a_ballot_reaches_the_app_log(app, redis, polls, audit_log, caplog):
    caplog.set_level(logging.DEBUG)
    for n in range(BATCH):
        box.store_ballot("e1", sealed(n))
    for n in range(BATCH):
        assert f"sealed-ballot-{n}" not in caplog.text


# ------------------------------------------------------------------------ receipts (for R6)
def test_store_ballot_returns_the_hash_that_ends_up_in_the_box(app, redis, polls, audit_log):
    hashes = {box.store_ballot("e1", sealed(n)) for n in range(BATCH)}
    assert hashes == {hashlib.sha256(sealed(n).encode()).hexdigest() for n in range(BATCH)}
    assert hashes == {r["ballot_hash"] for r in stored()}


# ------------------------------------------------------------------- end of polls: leftovers
def test_flush_pending_writes_the_last_part_full_batch(app, redis, polls, audit_log):
    box.store_ballot("e1", sealed(1))
    assert box.flush_pending("e1") == 1
    assert len(stored()) == 1 and audit_log[-1][2] == {"election_id": "e1", "count": 1}
    assert box.flush_pending("e1") == 0                          # nothing is written twice
    assert len(stored()) == 1


def test_elections_have_separate_waiting_lists(app, redis, polls, audit_log):
    box.store_ballot("e1", sealed(1))
    box.store_ballot("e2", sealed(2))
    box.flush_pending("e1")
    assert len(stored("e1")) == 1 and stored("e2") == []
    assert len(redis.lists["ballot_pending:e2"]) == 1


# ------------------------------------------------------------------------ misuse is refused
def test_no_ballot_is_accepted_when_polls_are_not_open(app, redis, audit_log, monkeypatch):
    def closed(election_id):
        raise ElectionError("POLLS_NOT_OPEN", "Voting is not open for this election.", 409)

    monkeypatch.setattr(f"{MODULE}.require_polls_open", closed)
    with pytest.raises(ElectionError):
        box.store_ballot("e1", sealed(1))
    assert redis.lists == {} and stored() == []


@pytest.mark.parametrize("bad", [None, "", 123, b"bytes", ["list"], "x" * (box.MAX_SEALED_LENGTH + 1)])
def test_a_missing_or_oversized_ballot_is_refused(app, redis, polls, bad):
    with pytest.raises(box.BallotBoxError) as e:
        box.store_ballot("e1", bad)
    assert e.value.status == 400 and e.value.code == "BAD_BALLOT"
    assert redis.lists == {}


@pytest.mark.parametrize("bad", [None, "", 5, "e" * 37])
def test_a_bad_election_id_is_refused(app, redis, polls, bad):
    with pytest.raises(box.BallotBoxError) as e:
        box.store_ballot(bad, sealed(1))
    assert e.value.code == "BAD_ELECTION" and redis.lists == {}


def test_if_the_write_fails_no_ballot_is_lost(app, redis, polls, audit_log):
    with db.engines["ballot"].begin() as c:
        c.execute(text("DROP TABLE ballots"))                    # the ballot database breaks
    box.store_ballot("e1", sealed(1))
    box.store_ballot("e1", sealed(2))
    with pytest.raises(Exception):
        box.store_ballot("e1", sealed(3))                        # the third one triggers the write
    assert len(redis.lists["ballot_pending:e1"]) == BATCH        # all three are back in the waiting list
    assert audit_log == []
