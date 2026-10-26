from flask import Blueprint

bp = Blueprint("ballot", __name__, url_prefix="/ballot")

from . import routes