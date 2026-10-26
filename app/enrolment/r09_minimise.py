"""R9 - Identity-document minimisation.

A data leak must not expose anyone's identity documents. Three rules:

  1. NO IMAGES. No route accepts a file: enrolment takes only the JSON fields R2 lists, and validate() refuses
     any extra field, so a scan or photo of a document has nowhere to go.
  2. NUMBERS ONLY SCRAMBLED, WITH THE RESULT AND A REFERENCE. Every identity check R2 makes is recorded here as
     (reference, document type, keyed hash of the number, MATCH/NO_MATCH, purpose, who, when). The hash is
     HMAC-SHA256 under a secret key (keyed_hash), so a stolen copy of the database cannot be reversed or
     checked against a list of guessed numbers without that key. The plain number is never stored anywhere.
  3. ANALYSIS USES A DE-IDENTIFIED COPY. GET /enrolment/analysis (auditor only) gives the roll with names,
     addresses, postcodes, email, exact date of birth, document hash and account removed. Each row keeps a
     pseudonym (a keyed hash of the elector id, so rows stay distinct but cannot be traced back without the
     key), division, state, age band and status. Every copy taken is audited.
"""
import uuid

from flask import jsonify

from . import bp
from .models import Elector
from .r09_models import IdentityCheck
from app.auth.r14_models import now
from app.common.audit import audit
from app.common.auth import current_user, login_required, role_required
from app.common.crypto import keyed_hash
from app.extensions import db

# (lowest age in the band, label), youngest first
AGE_BANDS = ((65, "65+"), (55, "55-64"), (45, "45-54"), (35, "35-44"), (25, "25-34"), (18, "18-24"), (0, "16-17"))


# ------------------------------------------------------------------ 2. scrambled number + result + reference
def record_identity_check(doc_type, doc_hash, matched, purpose, checked_by, elector_id=None):
    """Saves one identity check and returns its reference. Takes the HASH, never the number."""
    row = IdentityCheck(id=str(uuid.uuid4()), doc_type=doc_type, doc_hash=doc_hash,
                        result="MATCH" if matched else "NO_MATCH", purpose=purpose,
                        elector_id=elector_id, checked_by=checked_by, checked_at=now())
    db.session.add(row)
    db.session.commit()
    return row.id


def link_check_to_elector(reference, elector_id):
    """Once R2 has created the enrolment, the check it was based on points at it."""
    row = db.session.get(IdentityCheck, reference)
    if row is not None and row.elector_id is None:
        row.elector_id = elector_id
        db.session.commit()


# ------------------------------------------------------------------ 3. de-identified copy for analysis
def age_band(dob, today):
    age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
    return next(label for lowest, label in AGE_BANDS if age >= lowest)


def deidentified_roll(user):
    """The roll with everything that names or locates a person removed."""
    if not user or user.get("role") != "auditor":
        return None
    today = now().date()
    rows = [{"pseudonym": keyed_hash(f"r09-pseudonym:{e.id}")[:16], "division": e.division, "state": e.state,
             "age_band": age_band(e.dob, today), "status": e.status}
            for e in db.session.query(Elector).order_by(Elector.division, Elector.id).all()]
    audit("ENROLMENT_ANALYSIS_COPY", actor_id=user["id"], details={"rows": len(rows)})
    return rows


@bp.get("/analysis")                             # final URL: /enrolment/analysis
@login_required
@role_required("auditor")
def enrolment_analysis():
    rows = deidentified_roll(current_user())
    if rows is None:
        return jsonify({"error": "FORBIDDEN", "message": "Only an auditor can take an analysis copy."}), 403
    return jsonify({"rows": rows, "count": len(rows)})
