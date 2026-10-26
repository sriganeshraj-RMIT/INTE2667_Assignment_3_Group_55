"""R3 - the vote register (identity_db): who has voted in which election. It never says HOW anyone voted."""
from app.auth.r14_models import now
from app.extensions import db


class VoteRegister(db.Model):
    __tablename__ = "vote_register"

    # The pair (election, voter) is the primary key, so the DATABASE itself refuses a second row for the same
    # voter in the same election, whatever channel they use.
    election_id = db.Column(db.String(36), primary_key=True)
    voter_id = db.Column(db.String(36), primary_key=True)
    channel = db.Column(db.String(12), nullable=False)               # IN_PERSON | POSTAL | ONLINE
    marked_at = db.Column(db.DateTime, nullable=False, default=now)
    marked_by = db.Column(db.String(36), nullable=False)             # the officer, or the voter for ONLINE
