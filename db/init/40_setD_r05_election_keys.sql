USE identity_db;

CREATE TABLE election_keys (
  election_id        CHAR(36)    NOT NULL PRIMARY KEY,
  public_key_pem     TEXT        NOT NULL,
  locked_private_key TEXT        NOT NULL,
  threshold          INT         NOT NULL,
  share_count        INT         NOT NULL,
  created_by         CHAR(36)    NOT NULL,
  created_at         DATETIME    NOT NULL
);
