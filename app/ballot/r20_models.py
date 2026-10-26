"""R20 - the published head of each election's ballot chain (ballot_db, next to the ballots, no voter data)."""
from app.extensions import db


class BallotChainHead(db.Model):
    __bind_key__ = "ballot"
    __tablename__ = "ballot_chain_heads"

    election_id = db.Column(db.String(36), primary_key=True)
    head = db.Column(db.String(64), nullable=False)          # chain_head of the newest ballot
    length = db.Column(db.Integer, nullable=False)           # how many ballots are on the chain
    signature = db.Column(db.Text, nullable=False)           # Ed25519 signature of election_id, length and head
