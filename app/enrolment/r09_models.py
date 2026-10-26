"""R9 - table in identity_db (created in db/init/20_setB_r09_identity_checks.sql)."""
from app.extensions import db


class IdentityCheck(db.Model):
    """One identity check: scrambled document + result + reference. No number, image, name or address."""
    __tablename__ = "identity_checks"

    id = db.Column(db.String(36), primary_key=True)             # the reference
    doc_type = db.Column(db.String(20), nullable=False)
    doc_hash = db.Column(db.String(64), nullable=False)
    result = db.Column(db.String(8), nullable=False)            # MATCH | NO_MATCH
    purpose = db.Column(db.String(7), nullable=False)           # ENROL | ADDRESS
    elector_id = db.Column(db.String(36))
    checked_by = db.Column(db.String(36), nullable=False)
    checked_at = db.Column(db.DateTime, nullable=False)
