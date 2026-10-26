-- R11 - real-time security monitoring. Alerts are about the activity log, so they live in identity_db with it.
USE identity_db;

CREATE TABLE security_alerts (
  id                INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
  rule              VARCHAR(50)  NOT NULL,
  severity          VARCHAR(10)  NOT NULL,
  actor_id          VARCHAR(36)  NOT NULL,
  details           TEXT         NOT NULL,
  trigger_entry_id  BIGINT       NOT NULL,
  created_at        DATETIME     NOT NULL,
  status            VARCHAR(12)  NOT NULL DEFAULT 'OPEN',
  acknowledged_by   VARCHAR(36),
  acknowledged_at   DATETIME,
  UNIQUE KEY one_alert_per_rule_and_entry (rule, trigger_entry_id)
);

-- How far through audit_log the monitor has read (one row, id = 1).
CREATE TABLE security_monitor_state (
  id             INT  NOT NULL PRIMARY KEY,
  last_entry_id  BIGINT  NOT NULL DEFAULT 0
);
