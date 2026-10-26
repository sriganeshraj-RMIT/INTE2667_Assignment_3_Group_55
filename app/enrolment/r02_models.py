"""R2 - tables in identity_db (created in db/init/20_setB_r02_enrolment.sql)."""
from app.extensions import db


class IdentityRecord(db.Model):
    """MOCK official identity source (stands in for the government Document Verification Service).
    Only ever asked "do these details match?"; nothing from it is copied into the roll."""
    __tablename__ = "identity_records"

    id = db.Column(db.String(36), primary_key=True)
    given_name = db.Column(db.String(100), nullable=False)
    family_name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    doc_type = db.Column(db.String(20), nullable=False)
    doc_number = db.Column(db.String(20), nullable=False)
    citizen = db.Column(db.Boolean, nullable=False)


class PostcodeDivision(db.Model):
    __tablename__ = "postcode_divisions"

    postcode = db.Column(db.String(4), primary_key=True)
    division = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(50), nullable=False)


class EnrolmentCode(db.Model):
    """A single-use code posted to an address. Only a keyed hash of the code is kept."""
    __tablename__ = "enrolment_codes"

    id = db.Column(db.String(36), primary_key=True)          # the "reference" printed on the letter
    elector_id = db.Column(db.String(36), nullable=False)
    purpose = db.Column(db.String(10), nullable=False)       # ENROL | ADDRESS
    code_hash = db.Column(db.String(64), nullable=False)
    new_address_line = db.Column(db.String(200))
    new_suburb = db.Column(db.String(100))
    new_postcode = db.Column(db.String(4))
    new_state = db.Column(db.String(50))
    new_division = db.Column(db.String(100))
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    used_at = db.Column(db.DateTime)
