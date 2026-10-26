import os
from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only")

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

    return app
