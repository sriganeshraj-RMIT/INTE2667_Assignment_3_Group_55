from flask import Blueprint

bp = Blueprint("audit", __name__, url_prefix="/audit")

from . import routes