"""R17 - read and check the activity log (auditor or admin, after both sign-in steps)."""
import json

import click
from flask import jsonify, request

from . import bp
from .models import AuditEntry
from app.common.audit import verify_log
from app.common.auth import login_required, mfa_required, role_required
from app.common.crypto import public_key_b64
from app.extensions import db

READ_ROLES = ("auditor", "admin")


@bp.get("/verify")                               # final URL: /audit/verify
@login_required
@role_required(*READ_ROLES)
@mfa_required
def audit_verify():
    return jsonify({**verify_log(), "public_key": public_key_b64()})


@bp.get("/entries")
@login_required
@role_required(*READ_ROLES)
@mfa_required
def audit_entries():
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
    except ValueError:
        limit = 50
    rows = db.session.query(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit).all()
    return jsonify([{"id": r.id, "event": r.event, "actor_id": r.actor_id, "details": json.loads(r.details),
                     "created_at": r.created_at.isoformat(), "entry_hash": r.entry_hash,
                     "signature": r.signature} for r in rows])


@bp.cli.command("verify", help="R17: check that no activity log entry was changed, removed or added.")
def verify_command():
    result = verify_log()
    if result["valid"]:
        click.echo(f"OK: all {result['entries']} entries are intact.")
    else:
        raise click.ClickException(f"TAMPERED at entry {result['first_bad_entry']}: {result['problem']}")
