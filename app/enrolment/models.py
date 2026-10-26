"""Set B - the electoral roll in identity_db (table created in db/init/20_setB_electors.sql).

Used by R15 now; R2 (verified enrolment) adds to the same class later rather than making a second model.
"""
from app.extensions import db


class Elector(db.Model):
    __tablename__ = "electors"

    id = db.Column(db.String(36), primary_key=True)
    given_name = db.Column(db.String(100), nullable=False)
    family_name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    address_line = db.Column(db.String(200), nullable=False)
    suburb = db.Column(db.String(100), nullable=False)
    postcode = db.Column(db.String(4), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    division = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255))
    status = db.Column(db.String(10), nullable=False, default="PENDING")
    created_at = db.Column(db.DateTime)
    # R2 - added by db/init/20_setB_r02_enrolment.sql
    doc_hash = db.Column(db.String(64), unique=True)       # keyed hash of the identity document, never the number (R9)
    account_id = db.Column(db.String(36))                  # the voter account allowed to change this address
