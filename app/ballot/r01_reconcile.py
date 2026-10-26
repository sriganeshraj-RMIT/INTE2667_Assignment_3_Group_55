"""R1 - count reconciliation: the numbers on the two sides must agree, without linking anyone.

  GET /ballot/<election_id>/passes/reconcile   auditor, only after polls close

  issued  = voters marked off ONLINE (R3), i.e. passes signed by the issuer
  used    = spent passes (checker, ballot_db)
  stored  = ballots in the ballot box (after R4's last batch is written)

Rules: used <= issued (a pass cannot be used that was never issued) and used == stored (every used pass is
exactly one ballot). Anything else means extra or missing ballots, and PASS_COUNT_MISMATCH is audited.
"""
from flask import jsonify
from sqlalchemy import func, text

from . import bp
from .r01_models import SpentPass
from .r03_models import VoteRegister
from .r03_register import lookup_election
from .r04_ballot_box import flush_pending
from app.common.audit import audit
from app.common.auth import current_user, login_required, role_required
from app.extensions import db


def reconcile(user, election_id):
    if not user or user.get("role") != "auditor":
        return {"error": "FORBIDDEN", "message": "Only an auditor can reconcile the counts."}, 403
    election = lookup_election(election_id)
    if election is None:
        return {"error": "NOT_FOUND", "message": "No such election."}, 404
    if election["status"] != "CLOSED":
        return {"error": "POLLS_NOT_CLOSED", "message": "Reconcile after the polls close."}, 409

    flush_pending(election_id)                   # R4: write the last part-full batch first
    issued = db.session.query(func.count()).select_from(VoteRegister).filter(
        VoteRegister.election_id == election_id, VoteRegister.channel == "ONLINE").scalar()
    used = db.session.query(func.count()).select_from(SpentPass).filter(
        SpentPass.election_id == election_id).scalar()
    with db.engines["ballot"].connect() as connection:
        stored = connection.execute(text("SELECT COUNT(*) FROM ballots WHERE election_id = :eid"),
                                    {"eid": election_id}).scalar()
    result = {"issued": issued, "used": used, "stored": stored, "match": used <= issued and used == stored}
    if not result["match"]:
        audit("PASS_COUNT_MISMATCH", actor_id=user["id"], details={"election_id": election_id, **result})
    return result, 200


@bp.get("/<election_id>/passes/reconcile")
@login_required
@role_required("auditor")
def passes_reconcile(election_id):
    body, status = reconcile(current_user(), election_id)
    return jsonify(body), status
