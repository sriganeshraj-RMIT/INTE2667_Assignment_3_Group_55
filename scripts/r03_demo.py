"""R3 demo for the recording: one vote per voter, whatever channel they use. Runs in memory.

    python scripts/r03_demo.py
"""
import importlib
import os
import sys

os.environ["DATABASE_URL"] = "sqlite:///:memory:"            # never the real MySQL
os.environ["BALLOT_DATABASE_URL"] = "sqlite:///:memory:"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app import create_app                                   # noqa: E402
from app.ballot import r03_register as r03                   # noqa: E402
from app.extensions import db                                # noqa: E402
from tests.setd_helpers import add_account, add_election, create_base_tables   # noqa: E402

OFFICER = {"id": "officer-1", "role": "officer", "division": None, "state": None}


def step(title):
    print(f"\n=== {title}")


def attempt(label, action):
    try:
        action()
        print(f"   {label}: OK, marked off")
    except r03.RegisterError as e:
        print(f"   {label}: REFUSED ({e.code}: {e.message})")
    except RuntimeError as e:
        print(f"   {label}: FAILED half way ({e})")


def main():
    app = create_app()
    app.config["TESTING"] = True
    with app.app_context():
        try:
            importlib.import_module("app.audit.models")      # so the audit log table exists
        except ImportError:
            pass
        db.create_all()
        create_base_tables()
        add_election("demo", "OPEN", ("alice", "bob"))
        for account in ("vera", "victor"):
            add_account(account)
        add_account("wendy", division="Sydney", state="NSW")

        step("1. Vera votes in person: an officer marks her off at the polling place")
        attempt("officer, IN_PERSON", lambda: r03.staff_mark_off(OFFICER, "demo", "vera", "IN_PERSON"))

        step("2. Vera tries again by post, then online: the ONE register refuses both")
        attempt("officer, POSTAL", lambda: r03.staff_mark_off(OFFICER, "demo", "vera", "POSTAL"))
        attempt("Vera, ONLINE", lambda: r03.mark_off("vera", "demo", "ONLINE", "vera"))

        step("3. Victor votes online, but the step after marking fails: nothing is saved, he can try again")

        def pass_service_down():
            raise RuntimeError("the voting pass could not be signed")
        attempt("Victor, ONLINE (pass step fails)", lambda: r03.mark_off("victor", "demo", "ONLINE", "victor",
                                                                         then=pass_service_down))
        print(f"   Has Victor been marked off? {r03.has_voted('victor', 'demo')}")
        attempt("Victor, ONLINE (second try)", lambda: r03.mark_off("victor", "demo", "ONLINE", "victor",
                                                                    then=lambda: "voting pass"))
        attempt("Victor, POSTAL (a later attempt)", lambda: r03.staff_mark_off(OFFICER, "demo", "victor", "POSTAL"))

        step("4. Wendy is enrolled in Sydney, so she cannot be marked off in this election")
        attempt("officer, IN_PERSON", lambda: r03.staff_mark_off(OFFICER, "demo", "wendy", "IN_PERSON"))

        step("5. The polls close: no more voting")
        db.session.execute(db.text("UPDATE elections SET status = 'CLOSED' WHERE id = 'demo'"))
        db.session.commit()
        add_account("late")
        attempt("officer, IN_PERSON", lambda: r03.staff_mark_off(OFFICER, "demo", "late", "IN_PERSON"))

        step("6. The register holds who voted and by which channel, never how they voted")
        rows = db.session.execute(db.text("SELECT voter_id, channel FROM vote_register ORDER BY voter_id")).all()
        for voter, channel in rows:
            print(f"   {voter:<8} {channel}")


if __name__ == "__main__":
    main()
