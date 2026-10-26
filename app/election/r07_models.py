"""R7 / R13 - table for the count result (counted by R7, signed and published by R13)."""
import uuid

from app.auth.r14_models import now
from app.extensions import db


class CountResult(db.Model):                        # stored in identity_db
    __tablename__ = "count_results"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    election_id = db.Column(db.String(36), nullable=False)
    payload_json = db.Column(db.Text, nullable=False)           # the result, as canonical JSON text
    counted_by = db.Column(db.String(36), nullable=False)
    counted_at = db.Column(db.DateTime, nullable=False, default=now)
    signature = db.Column(db.Text)                              # filled in by R13 when published
    published_at = db.Column(db.DateTime)
