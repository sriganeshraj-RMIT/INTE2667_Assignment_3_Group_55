USE identity_db;

-- R3: one row per voter per election, whatever channel they used. The primary key makes a second row impossible.
CREATE TABLE vote_register (
  election_id CHAR(36)    NOT NULL,
  voter_id    CHAR(36)    NOT NULL,
  channel     VARCHAR(12) NOT NULL,          -- IN_PERSON | POSTAL | ONLINE
  marked_at   DATETIME    NOT NULL,
  marked_by   CHAR(36)    NOT NULL,
  PRIMARY KEY (election_id, voter_id)
);
