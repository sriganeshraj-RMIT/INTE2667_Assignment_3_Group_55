"""Small helpers shared by Sriganesh's tests (Set D). Nothing here is used by the app itself.

The shared login helpers are still stubs, so these tests do NOT depend on them. A test says
"act as this person" by replacing `current_user` in the module under test. When R8 is merged,
the only thing to update is `login_as` below (one place).
"""
from sqlalchemy import text

from app.extensions import db

USERS = {
    "counter":   {"id": "user-counter-1",  "role": "counting_officer", "division": None, "state": None},
    "counter2":  {"id": "user-counter-2",  "role": "counting_officer", "division": None, "state": None},
    "admin":     {"id": "user-admin-1",    "role": "admin",            "division": None, "state": None},
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
