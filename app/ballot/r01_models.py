"""R1 - tables (created in db/init/20_setB_r01_pass.sql)."""
from app.extensions import db


class PassKey(db.Model):
    """ISSUER (identity_db): the election's blind-signing key. The private half is encrypted."""
    __tablename__ = "pass_keys"

    election_id = db.Column(db.String(36), primary_key=True)
    n_hex = db.Column(db.Text, nullable=False)                  # public
    e = db.Column(db.Integer, nullable=False)                   # public
    private_enc = db.Column(db.Text, nullable=False)            # encrypted with a key derived from SECRET_KEY
    created_at = db.Column(db.DateTime, nullable=False)


class SpentPass(db.Model):
    """CHECKER (ballot_db): a used pass. No voter, time or IP column, on purpose."""
    __bind_key__ = "ballot"
    __tablename__ = "spent_passes"

    token_hash = db.Column(db.String(64), primary_key=True)    # SHA-256 of the pass token
    election_id = db.Column(db.String(36), nullable=False)
