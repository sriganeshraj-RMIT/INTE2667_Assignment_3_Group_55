-- R17 - tamper-proof activity log. Kept in identity_db (who did what), never next to the ballots.
USE identity_db;

CREATE TABLE audit_log (
  id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event       VARCHAR(100) NOT NULL,
  actor_id    VARCHAR(36)  NOT NULL,
  details     TEXT         NOT NULL,
  created_at  DATETIME     NOT NULL,
  prev_hash   CHAR(64)     NOT NULL,
  entry_hash  CHAR(64)     NOT NULL,
  signature   TEXT         NOT NULL
);

-- Rows can be added but never changed or deleted.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log is append-only';
