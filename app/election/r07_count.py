"""R7 - Two independent counts.

The count is done by TWO separately written programs (r07_count_a.py and r07_count_b.py). The result is only
saved if both give exactly the same answer. If they disagree, nothing is saved, a MISMATCH is logged and the
officer sees an error. That way a bug (or a quiet change) in one program cannot decide an election.

Who may count: a counting officer or an admin, each with live R14 access ("counting"), after polls have closed.
The ballots are opened here with 3 of the 5 key shares (R5), which the officer supplies in the request.
"""
import json

from flask import jsonify, request
from sqlalchemy import text

from . import bp
from app.auth.r14_elevation import elevation_required
from app.auth.r14_models import now
from app.common.audit import audit
from app.ballot import r05_open
from app.common.auth import current_user, login_required, role_required
from app.extensions import db
from . import r07_count_a, r07_count_b
from .r07_models import CountResult
from .r19_exclusions import approved_candidate_ids

COUNT_ROLES = ("counting_officer", "admin")


class CountError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def get_decrypted_ballots(election_id, shares):
    """R5 opens the ballot box with 3 of the 5 shares. Each ballot is a dict {candidate_id: preference_number}
    (1 = first choice); a ballot that could not be opened comes back as None and is counted as informal."""
    return r05_open.open_ballots(election_id, shares)


def canonical(payload):
    """The same result always gives the same bytes (needed for signing in R13)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def is_formal(ballot, candidate_ids):
    """Formal = every candidate numbered exactly once, 1..N, no repeats and no gaps."""
    if not isinstance(ballot, dict) or set(ballot) != set(candidate_ids):
        return False
    numbers = list(ballot.values())
    if not all(isinstance(n, int) and not isinstance(n, bool) for n in numbers):
        return False
    return sorted(numbers) == list(range(1, len(numbers) + 1))


def run_count(user, election_id, shares=None):
    if not user or user.get("role") not in COUNT_ROLES:
        audit("ELECTION_COUNT_REFUSED", actor_id=(user or {}).get("id", "anonymous"),
              details={"election_id": election_id, "role": (user or {}).get("role")})
        raise CountError("FORBIDDEN", "Only a counting officer or an admin can run the count.", 403)
    status = db.session.execute(text("SELECT status FROM elections WHERE id = :eid"), {"eid": election_id}).scalar()
    if status is None:
        raise CountError("NOT_FOUND", "No such election.", 404)
    if status != "CLOSED":
        raise CountError("POLLS_NOT_CLOSED", "The count can only start after the polls have closed.", 409)

    rows = db.session.execute(text("SELECT id, name FROM candidates WHERE election_id = :eid"),
                              {"eid": election_id}).all()
    names = {r[0]: r[1] for r in rows}
    candidate_ids = sorted(names)
    excluded = sorted(approved_candidate_ids(election_id))              # R19: only two-person-approved exclusions

    try:
        ballots = get_decrypted_ballots(election_id, shares)
    except r05_open.NoElectionKey:
        raise CountError("NO_ELECTION_KEY", "No election key was made for this election.", 409)
    except r05_open.BadShares:                                          # too few or wrong shares: the box stays shut
        audit("ELECTION_COUNT_BAD_SHARES", actor_id=user["id"], details={"election_id": election_id})
        raise CountError("BAD_SHARES", "At least 3 correct key shares are needed to open the ballots.", 403)

    formal = [b for b in ballots if is_formal(b, candidate_ids)]
    orders = [[cid for cid, _ in sorted(b.items(), key=lambda kv: kv[1])] for b in formal]

    result_a = r07_count_a.count(orders, candidate_ids, excluded)
    result_b = r07_count_b.count(orders, candidate_ids, excluded)
    if result_a != result_b:                                            # publish only if they match
        audit("ELECTION_COUNT_MISMATCH", actor_id=user["id"],
              details={"election_id": election_id, "winner_a": result_a["winner"], "winner_b": result_b["winner"]})
        raise CountError("COUNT_MISMATCH", "The two counting programs disagree. No result was saved.", 409)

    payload = {"election_id": election_id, "ballots_counted": len(formal),
               "ballots_informal": len(ballots) - len(formal), "excluded": excluded,
               "winner": result_a["winner"], "rounds": result_a["rounds"], "candidate_names": names,
               "counted_at": now().isoformat()}
    row = CountResult(election_id=election_id, payload_json=canonical(payload).decode(), counted_by=user["id"])
    db.session.add(row)
    db.session.commit()
    audit("ELECTION_COUNT_COMPLETED", actor_id=user["id"],
          details={"election_id": election_id, "result_id": row.id, "ballots_counted": len(formal)})
    return row, payload


# ----------------------------------------------------------------- route
@bp.post("/<election_id>/count")                 # final URL: /election/<election_id>/count
@login_required
@role_required("counting_officer", "admin")
@elevation_required("counting")
def count_votes(election_id):
    data = request.get_json(silent=True) or {}
    shares = data.get("shares")
    if shares is not None and not (isinstance(shares, list) and len(shares) <= 10
                                   and all(isinstance(s, str) and len(s) <= 200 for s in shares)):
        return jsonify({"error": "VALIDATION_FAILED", "message": "shares must be a short list of text values"}), 400
    try:
        row, payload = run_count(current_user(), election_id, shares)
    except CountError as e:
        return jsonify({"error": e.code, "message": e.message}), e.status
    return jsonify({"result_id": row.id, "result": payload})
