from app import create_app


def test_health_db_reports_both_databases():
    app = create_app()
    app.config["TESTING"] = True
    resp = app.test_client().get("/health/db")
    assert resp.status_code == 200
    assert resp.get_json() == {"identity_db": "up", "ballot_db": "up"}
