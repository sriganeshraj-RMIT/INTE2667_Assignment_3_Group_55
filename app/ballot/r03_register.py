"""R3 - One vote, every channel.

ONE central register is used by every way of voting (in person, postal, online). Marking a voter off is a single
database insert, and the database only allows one row per voter and election. So the second attempt, on ANY channel,
is refused, even if two requests arrive at the same moment.

mark_off() can run another step in the SAME transaction (the `then` argument). R1 uses that to sign the voter's
voting pass: either the voter is marked off AND gets the pass, or neither happens (all or nothing), so a voter is
never locked out by a failure half way.
"""
from flask import jsonify, request
from sqlalchemy import insert, select, text
from sqlalchemy.exc import IntegrityError

from . import bp
from app.auth.r14_models import now
from app.common.audit import audit
from app.common.auth import current_user, login_required, role_required
from app.common.validate import validate
from app.extensions import db
from .r03_models import VoteRegister

CHANNELS = ("IN_PERSON", "POSTAL", "ONLINE")
STAFF_CHANNELS = ("IN_PERSON", "POSTAL")          # an officer marks these; ONLINE is marked when R1 issues the pass
MARK_OFF_ROLES = ("officer",)

MARK_OFF_SCHEMA = {
    "voter_id": {"type": str, "max_length": 36, "required": True},
    "channel":  {"type": str, "max_length": 12, "required": True},
}


class RegisterError(Exception):
    def __init__(self, code, message, status):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


def error_response(e):
    return jsonify({"error": e.code, "message": e.message}), e.status


# ------------------------------------------------------------ what we look up
def lookup_voter(voter_id):
    row = db.session.execute(text("SELECT role, status, division, state FROM accounts WHERE id = :id"),
                             {"id": voter_id}).first()
    return None if row is None else {"role": row[0], "status": row[1], "division": row[2], "state": row[3]}


def lookup_election(election_id):
    row = db.session.execute(text("SELECT status, division, state FROM elections WHERE id = :eid"),
                             {"eid": election_id}).first()
    return None if row is None else {"status": row[0], "division": row[1], "state": row[2]}


def check_can_vote(voter_id, election_id):
    election = lookup_election(election_id)
    if election is None:
        raise RegisterError("NOT_FOUND", "No such election.", 404)
    if election["status"] != "OPEN":
        raise RegisterError("POLLS_NOT_OPEN", "Voting is only possible while the polls are open.", 409)
    voter = lookup_voter(voter_id)
    if voter is None or voter["role"] != "voter" or voter["status"] != "ACTIVE":
        raise RegisterError("VOTER_NOT_FOUND", "There is no active voter with that ID.", 404)
    if (voter["division"], voter["state"]) != (election["division"], election["state"]):
        raise RegisterError("WRONG_DIVISION", "This voter is enrolled in a different division.", 403)


# ------------------------------------------------------------- the one step
def mark_off(voter_id, election_id, channel, actor_id, then=None):
    """Marks the voter off. Raises RegisterError ALREADY_VOTED if they were already marked on ANY channel.

    `then` (optional) runs in the same transaction, for example "sign the voting pass" (R1). If it raises, the
    voter is NOT marked off and can try again. Returns whatever `then` returns.
    """
    if channel not in CHANNELS:
        raise RegisterError("INVALID_CHANNEL", "Channel must be IN_PERSON, POSTAL or ONLINE.", 400)
    check_can_vote(voter_id, election_id)
    try:
        # The database decides. A check-then-insert could let two simultaneous requests both through.
        db.session.execute(insert(VoteRegister).values(
            election_id=election_id, voter_id=voter_id, channel=channel, marked_by=actor_id,
            marked_at=now()))
    except IntegrityError:
        db.session.rollback()
        first = db.session.execute(select(VoteRegister.channel).where(
            VoteRegister.election_id == election_id, VoteRegister.voter_id == voter_id)).scalar()
        audit("BALLOT_DOUBLE_VOTE_BLOCKED", actor_id=actor_id,
              details={"election_id": election_id, "voter_id": voter_id,
                       "attempted_channel": channel, "first_channel": first})
        raise RegisterError("ALREADY_VOTED", "This voter has already voted.", 409)
    try:
        result = then() if then is not None else None
        db.session.commit()
    except Exception:
        db.session.rollback()                     # all or nothing: no mark-off without the rest of the step
        raise
    audit("BALLOT_VOTER_MARKED_OFF", actor_id=actor_id,                  # after our own commit, as R17 asks
          details={"election_id": election_id, "voter_id": voter_id, "channel": channel})
    return result


def has_voted(voter_id, election_id):
    return db.session.execute(select(VoteRegister.voter_id).where(
        VoteRegister.election_id == election_id, VoteRegister.voter_id == voter_id)).first() is not None


# ------------------------------------------------------------ staff channels
def staff_mark_off(user, election_id, voter_id, channel):
    """An officer marks a voter off at a polling place (IN_PERSON) or when a postal vote arrives (POSTAL)."""
    if not user or user.get("role") not in MARK_OFF_ROLES:
        audit("BALLOT_MARK_OFF_REFUSED", actor_id=(user or {}).get("id", "anonymous"),
              details={"election_id": election_id, "role": (user or {}).get("role")})
        raise RegisterError("FORBIDDEN", "Only an officer can mark a voter off.", 403)
    if channel not in STAFF_CHANNELS:
        raise RegisterError("INVALID_CHANNEL", "An officer marks IN_PERSON or POSTAL votes. "
                                               "Online votes are marked when the voting pass is issued.", 400)
    mark_off(voter_id, election_id, channel, actor_id=user["id"])


# ----------------------------------------------------------------- routes
@bp.post("/<election_id>/mark-off")              # final URL: /ballot/<election_id>/mark-off
@login_required
@role_required("officer")
def mark_off_route(election_id):
    data = validate(MARK_OFF_SCHEMA, request.get_json() or {})
    try:
        staff_mark_off(current_user(), election_id, data["voter_id"], data["channel"])
    except RegisterError as e:
        return error_response(e)
    return jsonify({"election_id": election_id, "status": "MARKED_OFF"}), 201


@bp.get("/<election_id>/my-status")              # a voter can only ask about THEMSELVES
@login_required
@role_required("voter")
def my_status(election_id):
    user = current_user()
    if not user or user.get("role") != "voter":
        return jsonify({"error": "FORBIDDEN", "message": "Only a voter can ask this."}), 403
    return jsonify({"election_id": election_id, "voted": has_voted(user["id"], election_id)})
