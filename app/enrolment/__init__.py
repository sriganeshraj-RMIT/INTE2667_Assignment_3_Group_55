from flask import Blueprint

bp = Blueprint("enrolment", __name__, url_prefix="/enrolment")

from . import routes