"""R5 - Opening the ballot box at the count.

Needs THRESHOLD (3) of the 5 shares. The private key is rebuilt in memory for this one count and is not saved.
Called by R7 (the count). Only R7's route, which needs a counting role, live R14 access and a closed election, uses it.
"""
from sqlalchemy import text

from app.extensions import db
from .r05_crypto import BadShares, open_ballot, unlock_private_key
from .r05_models import ElectionKey

__all__ = ["BadShares", "NoElectionKey", "open_ballots"]          # BadShares is re-used by R7


class NoElectionKey(Exception):
    pass


def open_ballots(election_id, shares):
    """Returns the opened ballots. A ballot that cannot be opened comes back as None (R7 counts it as informal)."""
    key = db.session.get(ElectionKey, election_id)
    if key is None:
        raise NoElectionKey()
    private_key = unlock_private_key(key.locked_private_key, shares)                    # raises BadShares
    with db.engines["ballot"].connect() as connection:                                  # the ballot database
        rows = connection.execute(text("SELECT ciphertext FROM ballots WHERE election_id = :eid ORDER BY id"),
                                  {"eid": election_id}).all()
    opened = []
    for (ciphertext,) in rows:
        try:
            sealed = bytes(ciphertext).decode() if isinstance(ciphertext, (bytes, bytearray, memoryview)) else ciphertext
        except UnicodeDecodeError:                     # not even text: it cannot be a sealed ballot
            opened.append(None)
            continue
        opened.append(open_ballot(private_key, election_id, sealed))
    return opened
