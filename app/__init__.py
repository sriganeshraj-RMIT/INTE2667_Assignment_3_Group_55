import os
from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///:memory:")
    app.config["SQLALCHEMY_BINDS"] = {"ballot": os.environ.get("BALLOT_DATABASE_URL", "sqlite:///:memory:")}
    from .extensions import db
    db.init_app(app)

    from .auth import bp as auth_bp
    from .enrolment import bp as enrolment_bp
    from .ballot import bp as ballot_bp
    from .election import bp as election_bp
    from .audit import bp as audit_bp

    for bp in (auth_bp, enrolment_bp, ballot_bp, election_bp, audit_bp):
        app.register_blueprint(bp)

    @app.get("/health")
    def health():
        return {"status": "ok"}
    @app.get("/health/db")
    def health_db():
        from sqlalchemy import text
        status = {}
        for name, engine in (("identity_db", db.engine), ("ballot_db", db.engines["ballot"])):
            try:
                with engine.connect() as c:
                    c.execute(text("SELECT 1"))
                status[name] = "up"
            except Exception:
                status[name] = "down"
        return status, (200 if all(v == "up" for v in status.values()) else 503)

    return app
