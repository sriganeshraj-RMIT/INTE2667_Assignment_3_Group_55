USE identity_db;

CREATE TABLE count_results (
  id           CHAR(36)  NOT NULL PRIMARY KEY,
  election_id  CHAR(36)  NOT NULL,
  payload_json LONGTEXT  NOT NULL,
  counted_by   CHAR(36)  NOT NULL,
  counted_at   DATETIME  NOT NULL,
  signature    TEXT,
  published_at DATETIME
);
