from flask import Blueprint

bp = Blueprint("election", __name__, url_prefix="/election")

from . import routes