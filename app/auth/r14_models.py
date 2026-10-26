"""R14 - table for time-limited admin access (request -> approve -> switches itself off)."""
import uuid
from datetime import datetime, timezone

from app.extensions import db


def now():
    """Current time in UTC. It is a function so the tests can move the clock."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AccessGrant(db.Model):                        # stored in identity_db
    __tablename__ = "access_grants"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    requester_id = db.Column(db.String(36), nullable=False)
    ticket_no = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    scope = db.Column(db.String(20), nullable=False)             # counting | results
    status = db.Column(db.String(10), nullable=False, default="PENDING")   # PENDING | APPROVED
    approver_id = db.Column(db.String(36))
    requested_at = db.Column(db.DateTime, nullable=False, default=now)
    approved_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
