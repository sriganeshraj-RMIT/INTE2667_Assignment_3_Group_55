CREATE DATABASE IF NOT EXISTS ballot_db;
USE ballot_db;

CREATE TABLE ballots (
  id              CHAR(32)     NOT NULL PRIMARY KEY,
  election_id     CHAR(36)     NOT NULL,
  ciphertext      BLOB         NOT NULL,
  ballot_hash     CHAR(64)     NOT NULL,
  definition_fp   CHAR(64)     NOT NULL,
  batch_id        CHAR(36)     NOT NULL,
  chain_prev      CHAR(64),
  chain_head      CHAR(64)
);

CREATE TABLE audit_log (
  id          BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
  event       VARCHAR(100)  NOT NULL,
  actor_id    CHAR(36),
  details     JSON,
  prev_hash   CHAR(64),
  entry_hash  CHAR(64)      NOT NULL,
  signature   TEXT,
  created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
);