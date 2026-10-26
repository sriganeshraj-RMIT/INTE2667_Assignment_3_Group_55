"""R5 - table for the election key (identity_db). It holds the public key and the LOCKED private key only."""
from app.auth.r14_models import now
from app.extensions import db


class ElectionKey(db.Model):
    __tablename__ = "election_keys"

    election_id = db.Column(db.String(36), primary_key=True)         # one key per election
    public_key_pem = db.Column(db.Text, nullable=False)
    locked_private_key = db.Column(db.Text, nullable=False)          # useless without 3 of the 5 shares
    threshold = db.Column(db.Integer, nullable=False)
    share_count = db.Column(db.Integer, nullable=False)
    created_by = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
