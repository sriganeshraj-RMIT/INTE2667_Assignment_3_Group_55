"""R4 - No clues in the ballot box.

The ballot box must not hold anything that could link a ballot back to the voter who cast it.
The mark-off list (R3) knows WHO voted and WHEN. If the ballot box also showed when each ballot arrived,
the two could be lined up and the secret vote would be gone. So, in plain words:

  1. RANDOM IDS: each ballot gets 32 random hex characters as its id (not 1, 2, 3 ...), so the id says nothing
     about arrival order.
  2. NO TIMES, NO IPS, NO VOTER: store_ballot() is only ever given the election and the sealed ballot.
     The ballots table has no time, IP or voter column, and this file never adds one.
  3. SHUFFLED BATCH WRITES: a ballot is not written the moment it arrives. It waits in a short Redis list.
     When BATCH_SIZE ballots have arrived they are shuffled and written together, with one batch id.
     Inside a batch the database order is random, so row order cannot be matched with mark-off times.
  4. CLEAN LOGS: nothing about a single ballot is logged. One audit entry per batch says only
     "N ballots were stored for election E", as the "system" actor.

Who calls what:
  * The casting route (after R1/R3 mark-off) calls store_ballot(election_id, sealed_ballot).
    It returns the ballot's hash, which R6 will turn into the voter's confirmation code.
  * When polls close, the count (R7) must call flush_pending(election_id) first, or up to
    BATCH_SIZE - 1 ballots would still be waiting in Redis.
"""
import hashlib
import secrets
import uuid

from flask import current_app
from sqlalchemy import text

from app.common.audit import audit
from app.election.r10_lock import require_polls_open
from app.extensions import db, get_redis

BATCH_SIZE = 10                 # ballots held back before a shuffled write (config: BALLOT_BATCH_SIZE)
MAX_SEALED_LENGTH = 20000       # a sealed ballot is a few kB; refuse anything far bigger
_shuffler = secrets.SystemRandom()


class BallotBoxError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def _pending_key(election_id):
    return f"ballot_pending:{election_id}"


def _batch_size():
    return int(current_app.config.get("BALLOT_BATCH_SIZE", BATCH_SIZE))


def new_ballot_id():
    """32 random hex characters. Fits ballots.id CHAR(32). Never sequential."""
    return secrets.token_hex(16)


def _check(election_id, sealed):
    if not isinstance(election_id, str) or not 0 < len(election_id) <= 36:
        raise BallotBoxError("BAD_ELECTION", "Unknown election.", 400)
    if not isinstance(sealed, str) or not sealed or len(sealed) > MAX_SEALED_LENGTH:
        raise BallotBoxError("BAD_BALLOT", "The sealed ballot is missing or too large.", 400)


def store_ballot(election_id, sealed):
    """Puts one sealed ballot in the box. Returns its SHA-256 hash (for the R6 confirmation code).

    Only the election and the sealed text come in, so no voter, time or IP can end up in the box.
    """
    _check(election_id, sealed)
    require_polls_open(election_id)                  # R10: refuses outside polling times or if the ballot was changed
    r = get_redis()
    waiting = r.rpush(_pending_key(election_id), sealed)
    if waiting >= _batch_size():
        _flush(election_id)
    return hashlib.sha256(sealed.encode()).hexdigest()


def flush_pending(election_id):
    """Writes whatever is still waiting (the last, part-full batch). Call it when polls close. Returns the count."""
    return _flush(election_id)


def _take_pending(election_id):
    """Reads and empties the waiting list in one step, so two requests cannot write the same ballots twice."""
    pipe = get_redis().pipeline(transaction=True)
    pipe.lrange(_pending_key(election_id), 0, -1)
    pipe.delete(_pending_key(election_id))
    waiting, _ = pipe.execute()
    return [w.decode() if isinstance(w, (bytes, bytearray)) else w for w in waiting]


def _flush(election_id):
    waiting = _take_pending(election_id)
    if not waiting:
        return 0
    _shuffler.shuffle(waiting)                       # arrival order is thrown away here
    definition_fp = db.session.execute(text("SELECT definition_fp FROM elections WHERE id = :eid"),
                                       {"eid": election_id}).scalar() or ""
    batch_id = str(uuid.uuid4())
    rows = [{"id": new_ballot_id(), "eid": election_id, "ct": sealed.encode(),
             "h": hashlib.sha256(sealed.encode()).hexdigest(), "fp": definition_fp, "batch": batch_id}
            for sealed in waiting]
    try:
        with db.engines["ballot"].begin() as connection:                 # all of the batch, or none of it
            connection.execute(
                text("INSERT INTO ballots (id, election_id, ciphertext, ballot_hash, definition_fp, batch_id) "
                     "VALUES (:id, :eid, :ct, :h, :fp, :batch)"), rows)
    except Exception:
        get_redis().rpush(_pending_key(election_id), *waiting)            # put them back: never lose a ballot
        raise
    audit("BALLOT_BATCH_STORED", actor_id="system",                      # no ids, no hashes, no contents
          details={"election_id": election_id, "count": len(rows)})
    return len(rows)
