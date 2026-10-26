"""R19 - table for candidate exclusions (propose -> a different delegate approves)."""
import uuid

from app.auth.r14_models import now
from app.extensions import db


class Exclusion(db.Model):                          # stored in identity_db
    __tablename__ = "exclusions"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    election_id = db.Column(db.String(36), nullable=False)
    candidate_id = db.Column(db.String(36), nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="PENDING")     # PENDING | APPROVED | REJECTED
    proposed_by = db.Column(db.String(36), nullable=False)
    approved_by = db.Column(db.String(36))
    proposed_at = db.Column(db.DateTime, nullable=False, default=now)
    decided_at = db.Column(db.DateTime)
