import os
import redis
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

_redis = None
def get_redis():
    global _redis
    if _redis is None:
        _redis = redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
    return _redis