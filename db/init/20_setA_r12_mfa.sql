-- R12 - second sign-in step. Runs after 01_identity.sql.
USE identity_db;

ALTER TABLE accounts
  ADD COLUMN mfa_last_step    BIGINT   NULL,
  ADD COLUMN mfa_failed       INT      NOT NULL DEFAULT 0,
  ADD COLUMN mfa_locked_until DATETIME NULL;

-- One pending emailed code per voter (only a keyed hash of the code is stored).
CREATE TABLE mfa_email_codes (
  account_id CHAR(36) NOT NULL PRIMARY KEY,
  code_hash  CHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  attempts   INT      NOT NULL DEFAULT 0
);
