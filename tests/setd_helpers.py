"""Small helpers shared by Sriganesh's tests (Set D). Nothing here is used by the app itself.

The shared login helpers are still stubs, so these tests do NOT depend on them. A test says
"act as this person" by replacing `current_user` in the module under test. When R8 is merged,
the only thing to update is `login_as` below (one place).
"""
import hashlib
import uuid

from sqlalchemy import text

from app.extensions import db

USERS = {
    "counter":   {"id": "user-counter-1",  "role": "counting_officer", "division": None, "state": None},
    "counter2":  {"id": "user-counter-2",  "role": "counting_officer", "division": None, "state": None},
    "admin":     {"id": "user-admin-1",    "role": "admin",            "division": None, "state": None},
    "admin2":    {"id": "user-admin-2",    "role": "admin",            "division": None, "state": None},
    "custodian": {"id": "user-custodian-1", "role": "custodian",       "division": None, "state": None},
    "delegate1": {"id": "user-delegate-1", "role": "delegate",         "division": None, "state": None},
    "delegate2": {"id": "user-delegate-2", "role": "delegate",         "division": None, "state": None},
    "voter":     {"id": "user-voter-1",    "role": "voter",            "division": "Melbourne", "state": "VIC"},
    "auditor":   {"id": "user-auditor-1",  "role": "auditor",          "division": None, "state": None},
}


def login_as(monkeypatch, who, *module_paths):
    """Act as USERS[who] (or nobody if who is None) inside the given modules."""
    user = USERS[who] if who else None
    for path in module_paths:
        monkeypatch.setattr(f"{path}.current_user", lambda user=user: user)


def create_base_tables():
    """The `elections` and `candidates` tables belong to other people. Make small SQLite copies for tests."""
    db.session.execute(text("""CREATE TABLE IF NOT EXISTS elections (
        id TEXT PRIMARY KEY, name TEXT, division TEXT, state TEXT, definition_fp TEXT, status TEXT)"""))
    db.session.execute(text("""CREATE TABLE IF NOT EXISTS candidates (
        id TEXT PRIMARY KEY, election_id TEXT, name TEXT, party TEXT, ballot_pos INTEGER)"""))
    db.session.commit()


def add_election(election_id="e1", status="CLOSED", candidates=("c1", "c2", "c3")):
    db.session.execute(text("INSERT INTO elections (id, name, division, state, status) "
                            "VALUES (:id, 'Test', 'Melbourne', 'VIC', :status)"),
                       {"id": election_id, "status": status})
    for pos, cid in enumerate(candidates, 1):
        db.session.execute(text("INSERT INTO candidates (id, election_id, name, party, ballot_pos) "
                                "VALUES (:id, :eid, :name, 'P', :pos)"),
                           {"id": cid, "eid": election_id, "name": f"Candidate {cid}", "pos": pos})
    db.session.commit()


def create_ballot_tables():
    """The `ballots` table lives in the BALLOT database. Make a small SQLite copy for tests."""
    with db.engines["ballot"].begin() as connection:
        connection.execute(text("""CREATE TABLE IF NOT EXISTS ballots (
            id TEXT PRIMARY KEY, election_id TEXT NOT NULL, ciphertext BLOB NOT NULL, ballot_hash TEXT NOT NULL,
            definition_fp TEXT NOT NULL, batch_id TEXT NOT NULL, chain_prev TEXT, chain_head TEXT)"""))


def store_sealed(election_id, sealed, ballot_id=None):
    """Put one sealed ballot (text or raw bytes) in the ballot database. The casting code of R1/R4 does this for real."""
    raw = sealed.encode() if isinstance(sealed, str) else sealed
    with db.engines["ballot"].begin() as connection:
        connection.execute(
            text("INSERT INTO ballots (id, election_id, ciphertext, ballot_hash, definition_fp, batch_id) "
                 "VALUES (:id, :eid, :ct, :h, 'fp', 'batch-1')"),
            {"id": ballot_id or uuid.uuid4().hex, "eid": election_id, "ct": raw,
             "h": hashlib.sha256(raw).hexdigest()})
