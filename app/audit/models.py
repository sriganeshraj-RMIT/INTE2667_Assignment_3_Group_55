"""R17 - the activity log table (identity_db). Rows are only ever added, never changed."""
from app.extensions import db


class AuditEntry(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event = db.Column(db.String(100), nullable=False)
    actor_id = db.Column(db.String(36), nullable=False)
    details = db.Column(db.Text, nullable=False)                 # canonical JSON text
    created_at = db.Column(db.DateTime, nullable=False)
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.Text, nullable=False)
