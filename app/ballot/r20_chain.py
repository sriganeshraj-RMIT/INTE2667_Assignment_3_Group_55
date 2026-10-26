"""R20 - Tamper-resistant ballot box.

Every ballot is a link in a chain, like the activity log (R17):
  * chain_prev = the chain_head of the ballot linked before it (64 zeros for the first ballot);
  * chain_head = SHA-256 of chain_prev + this ballot's id, election, ballot hash, definition and batch.
The newest chain_head (the HEAD) and the number of ballots are kept in ballot_chain_heads and SIGNED (Ed25519),
so they can be published. Then:
  * change a ballot      -> its ballot_hash or chain_head no longer matches;
  * remove a ballot      -> the chain has a gap, or is shorter than the signed length;
  * add a fake ballot    -> it is not on the chain, or two ballots claim the same place;
  * change the head      -> the signature no longer matches.
verify_ballot_chain() walks the chain and names the first problem. In MySQL the ballots table also refuses
UPDATE and DELETE (triggers in db/init/30_setC_r20_ballot_chain.sql).

R4's _flush() calls link_batch() inside the same transaction that writes the batch, so ballots and the head
are saved together or not at all. The order of the chain is the shuffled R4 order, so it gives no clue either.
"""
import hashlib
import json

import click
from flask import jsonify
from sqlalchemy import text

from . import bp
from app.common.audit import audit
from app.common.auth import current_user, login_required, mfa_required, role_required
from app.common.crypto import chain_hash, public_key_b64, sign, verify
from app.extensions import db
from .r20_models import BallotChainHead

GENESIS = "0" * 64
VERIFY_ROLES = ("auditor", "admin")

_SELECT_HEAD = "SELECT head, length FROM ballot_chain_heads WHERE election_id = :eid"
_SELECT_HEAD_LOCKED = "SELECT head, length FROM ballot_chain_heads WHERE election_id = :eid FOR UPDATE"  # MySQL lock


def link_content(ballot_id, election_id, ballot_hash, definition_fp, batch_id):
    """The exact bytes each link hashes. ballot_hash covers the sealed ballot itself."""
    return json.dumps({"id": ballot_id, "election_id": election_id, "ballot_hash": ballot_hash,
                       "definition_fp": definition_fp, "batch_id": batch_id},
                      sort_keys=True, separators=(",", ":")).encode()


def head_message(election_id, length, head):
    """What is signed: the election, how many ballots, and the newest link."""
    return f"{election_id}:{length}:{head}".encode()


def link_batch(connection, election_id, rows):
    """Adds `prev` and `head` to each row (R4's dict keys: id, eid, h, fp, batch) and moves the signed head on.

    Must be called inside the transaction that inserts the rows.
    """
    locked = _SELECT_HEAD_LOCKED if connection.dialect.name == "mysql" else _SELECT_HEAD
    current = connection.execute(text(locked), {"eid": election_id}).first()
    prev, length = (current[0], current[1]) if current else (GENESIS, 0)
    for row in rows:
        row["prev"] = prev
        row["head"] = chain_hash(prev, link_content(row["id"], row["eid"], row["h"], row["fp"], row["batch"]))
        prev = row["head"]
    length += len(rows)
    values = {"eid": election_id, "head": prev, "len": length, "sig": sign(head_message(election_id, length, prev))}
    if current:
        connection.execute(text("UPDATE ballot_chain_heads SET head = :head, length = :len, signature = :sig "
                                "WHERE election_id = :eid"), values)
    else:
        connection.execute(text("INSERT INTO ballot_chain_heads (election_id, head, length, signature) "
                                "VALUES (:eid, :head, :len, :sig)"), values)
    return prev


def _as_bytes(value):
    if isinstance(value, str):
        return value.encode()
    return bytes(value) if value is not None else b""


def verify_ballot_chain(election_id):
    """Re-checks every ballot of one election. Returns {"valid", "length", "head", "problem", "bad_ballot"}."""
    def result(valid, problem=None, bad=None, length=0, head=None):
        return {"election_id": election_id, "valid": valid, "length": length, "head": head,
                "problem": problem, "bad_ballot": bad}

    db.session.expire_all()                      # always read the head fresh, never from the session cache
    stored = db.session.get(BallotChainHead, election_id)
    with db.engines["ballot"].connect() as c:
        ballots = c.execute(text("SELECT id, election_id, ciphertext, ballot_hash, definition_fp, batch_id, "
                                 "chain_prev, chain_head FROM ballots WHERE election_id = :eid"),
                            {"eid": election_id}).mappings().all()

    if stored is None:
        return result(not ballots, None if not ballots else "ballots are in the box but there is no chain head")
    head, length = stored.head, stored.length
    if not verify(head_message(election_id, length, head), stored.signature):
        return result(False, "the signed head was changed", length=length, head=head)

    by_prev = {}
    for b in ballots:
        if b["chain_prev"] is None or b["chain_prev"] in by_prev:
            return result(False, "a ballot was added that is not on the chain", b["id"], length, head)
        by_prev[b["chain_prev"]] = b

    prev, count = GENESIS, 0
    while prev in by_prev:
        b = by_prev.pop(prev)
        if hashlib.sha256(_as_bytes(b["ciphertext"])).hexdigest() != b["ballot_hash"]:
            return result(False, "a sealed ballot was changed", b["id"], length, head)
        expected = chain_hash(prev, link_content(b["id"], b["election_id"], b["ballot_hash"],
                                                 b["definition_fp"], b["batch_id"]))
        if expected != b["chain_head"]:
            return result(False, "a ballot's details were changed", b["id"], length, head)
        prev, count = b["chain_head"], count + 1

    if by_prev:
        return result(False, "a ballot was removed (the chain has a gap)", None, length, head)
    if count > length:
        return result(False, "a ballot was added after the signed head", None, length, head)
    if prev != head or count != length:
        return result(False, "a ballot was removed (the chain is shorter than the signed head)", None, length, head)
    return result(True, length=length, head=head)


def _bad_id(election_id):
    return not 0 < len(election_id) <= 36


@bp.get("/<election_id>/chain")                  # public on purpose: the signed head can be published anywhere
def chain_head(election_id):
    if _bad_id(election_id):
        return jsonify({"error": "BAD_ELECTION", "message": "Unknown election."}), 400
    row = db.session.get(BallotChainHead, election_id)
    if row is None:
        return jsonify({"error": "NOT_FOUND", "message": "No ballots have been stored for this election yet."}), 404
    return jsonify({"election_id": election_id, "head": row.head, "length": row.length, "signature": row.signature,
                    "signed_message": head_message(election_id, row.length, row.head).decode(),
                    "public_key": public_key_b64()})


@bp.get("/<election_id>/chain/verify")
@login_required
@role_required(*VERIFY_ROLES)
@mfa_required
def chain_verify(election_id):
    if _bad_id(election_id):
        return jsonify({"error": "BAD_ELECTION", "message": "Unknown election."}), 400
    outcome = verify_ballot_chain(election_id)
    if not outcome["valid"]:
        user = current_user() or {}
        audit("BALLOT_CHAIN_TAMPERED", actor_id=user.get("id", "anonymous"),
              details={"election_id": election_id, "problem": outcome["problem"]})
    return jsonify(outcome)


@bp.cli.command("verify-chain", help="R20: check that no ballot of an election was changed, removed or added.")
@click.argument("election_id")
def verify_chain_command(election_id):
    outcome = verify_ballot_chain(election_id)
    if outcome["valid"]:
        click.echo(f"OK: all {outcome['length']} ballots of {election_id} are intact.")
    else:
        raise click.ClickException(f"TAMPERED: {outcome['problem']} (ballot {outcome['bad_ballot']})")
