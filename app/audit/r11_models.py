"""R11 - security alerts raised by the monitor, and how far through the activity log it has read (identity_db)."""
from app.extensions import db


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"
    __table_args__ = (db.UniqueConstraint("rule", "trigger_entry_id"),)        # one alert per rule per log entry

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    rule = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(10), nullable=False)                        # MEDIUM, HIGH or CRITICAL
    actor_id = db.Column(db.String(36), nullable=False)                        # who the log entry was about
    details = db.Column(db.Text, nullable=False)                               # JSON, never secrets
    trigger_entry_id = db.Column(db.Integer, nullable=False)                   # the audit_log row that set it off
    created_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(12), nullable=False, default="OPEN")          # OPEN or ACKNOWLEDGED
    acknowledged_by = db.Column(db.String(36))
    acknowledged_at = db.Column(db.DateTime)


class MonitorState(db.Model):
    __tablename__ = "security_monitor_state"

    id = db.Column(db.Integer, primary_key=True)                               # always 1
    last_entry_id = db.Column(db.Integer, nullable=False, default=0)
