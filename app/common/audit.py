"""R17 - tamper-proof activity log.

    audit("ELECTION_EXCLUSION_APPROVED", actor_id=user["id"], details={"exclusion_id": ex.id})

Each call adds ONE row to audit_log:
  * who did it (actor_id), what (event), the details, and the time;
  * prev_hash: the entry_hash of the row before it, so the rows form a chain;
  * entry_hash: SHA-256 of prev_hash plus this row's content;
  * signature: the platform's Ed25519 signature of entry_hash (app/common/crypto.py).
Changing, deleting or inserting any row breaks the chain or a signature, and verify_log() finds the first bad row.
In MySQL the table also refuses UPDATE and DELETE (triggers in db/init/25_setA_r17_audit_log.sql).

Call audit() AFTER your own db.session.commit(): it commits its own row.
Never put passwords, codes, tokens or ballot contents in details.
"""
import json
import logging
import threading

from app.extensions import db

GENESIS = "0" * 64
_lock = threading.Lock()                       # one writer at a time inside this process
log = logging.getLogger("evp.audit")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _content(event, actor_id, details_json, created_at):
    return _canonical({"event": event, "actor_id": actor_id, "details": details_json,
                       "created_at": created_at.strftime("%Y-%m-%dT%H:%M:%S")}).encode()


def audit(event: str, actor_id: str, details: dict) -> None:
    """Appends a chained, signed entry to the audit log. R17."""
    from app.audit.models import AuditEntry          # imported here to avoid a circular import
    from app.auth.r14_models import now
    from app.common.crypto import chain_hash, sign

    details_json = _canonical(details or {})
    created_at = now().replace(microsecond=0)        # MySQL DATETIME keeps whole seconds
    with _lock:                                      # the app runs as one process (flask run), so this is enough
        last = db.session.query(AuditEntry.entry_hash).order_by(AuditEntry.id.desc()).first()
        prev = last[0] if last else GENESIS
        entry_hash = chain_hash(prev, _content(event, actor_id or "anonymous", details_json, created_at))
        db.session.add(AuditEntry(event=event, actor_id=actor_id or "anonymous", details=details_json,
                                  created_at=created_at, prev_hash=prev, entry_hash=entry_hash,
                                  signature=sign(entry_hash.encode())))
        db.session.commit()
    log.info("%s actor=%s", event, actor_id)


def verify_log():
    """Re-checks the whole chain. Returns {"valid", "entries", "first_bad_entry", "problem"}."""
    from app.audit.models import AuditEntry
    from app.common.crypto import chain_hash, verify

    prev, count = GENESIS, 0
    for row in db.session.query(AuditEntry).order_by(AuditEntry.id).yield_per(500):
        count += 1
        problem = None
        if row.prev_hash != prev:
            problem = "a row before this one was removed, added or changed"
        elif chain_hash(prev, _content(row.event, row.actor_id, row.details, row.created_at)) != row.entry_hash:
            problem = "this row was changed"
        elif not verify(row.entry_hash.encode(), row.signature):
            problem = "the signature does not match"
        if problem:
            return {"valid": False, "entries": count, "first_bad_entry": row.id, "problem": problem}
        prev = row.entry_hash
    return {"valid": True, "entries": count, "first_bad_entry": None, "problem": None}
