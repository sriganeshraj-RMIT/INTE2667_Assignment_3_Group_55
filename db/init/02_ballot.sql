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

-- The activity log (R17) lives in identity_db (25_setA_r17_audit_log.sql), not next to the ballots.
