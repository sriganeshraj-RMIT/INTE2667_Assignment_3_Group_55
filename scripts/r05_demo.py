"""R5 demo for the recording: sealed ballots and the 3-of-5 key shares. Runs in memory, touches no real database.

    python scripts/r05_demo.py
"""
import os
import sys

os.environ["DATABASE_URL"] = "sqlite:///:memory:"            # never the real MySQL
os.environ["BALLOT_DATABASE_URL"] = "sqlite:///:memory:"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text                                  # noqa: E402

from app import create_app                                   # noqa: E402
from app.ballot import r05_crypto, r05_keys, r05_open        # noqa: E402
from app.extensions import db                                # noqa: E402

CUSTODIAN = {"id": "demo-custodian", "role": "custodian"}


def step(title):
    print(f"\n=== {title}")


def main():
    app = create_app()
    with app.app_context():
        db.create_all()
        db.session.execute(text("CREATE TABLE elections (id TEXT PRIMARY KEY, status TEXT)"))
        db.session.execute(text("INSERT INTO elections VALUES ('demo', 'DRAFT')"))
        db.session.commit()
        with db.engines["ballot"].begin() as connection:
            connection.execute(text("CREATE TABLE ballots (id TEXT PRIMARY KEY, election_id TEXT, ciphertext BLOB)"))

        step("1. Key ceremony: a custodian makes the election key before the polls open")
        public_pem, shares = r05_keys.run_ceremony(CUSTODIAN, "demo")
        print("Public key made (voters' devices use it). Private key is stored LOCKED.")
        print(f"{len(shares)} shares made, shown once, never stored. Example share: {shares[0][:24]}...")

        step("2. Voters' devices lock their ballots with the public key")
        for i, ballot in enumerate([{"alice": 1, "bob": 2}, {"bob": 1, "alice": 2}, {"alice": 1, "bob": 2}], 1):
            sealed = r05_crypto.seal_ballot(public_pem, "demo", ballot)
            with db.engines["ballot"].begin() as connection:
                connection.execute(text("INSERT INTO ballots VALUES (:id, 'demo', :ct)"),
                                   {"id": f"ballot-{i}", "ct": sealed.encode()})
            print(f"Ballot {i} in the box: {sealed[:60]}...   (contains 'alice'? {'alice' in sealed})")

        step("3. Polls close. Only 2 officials turn up: the box stays shut")
        try:
            r05_open.open_ballots("demo", shares[:2])
        except r05_crypto.BadShares as e:
            print("REFUSED:", e)

        step("4. A wrong share is also refused")
        try:
            r05_open.open_ballots("demo", [shares[0], shares[1], shares[2][:-1] + "0"])
        except r05_crypto.BadShares as e:
            print("REFUSED:", e)

        step("5. Three officials (shares 1, 3 and 5) open the box")
        for ballot in r05_open.open_ballots("demo", [shares[0], shares[2], shares[4]]):
            print("Opened:", ballot)


if __name__ == "__main__":
    main()
