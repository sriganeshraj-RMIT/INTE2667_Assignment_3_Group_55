-- R20 - tamper-resistant ballot box. Lives next to the ballots in ballot_db; holds no voter data.
USE ballot_db;

-- The signed head of each election's ballot chain (newest link + number of ballots).
CREATE TABLE ballot_chain_heads (
  election_id  CHAR(36)  NOT NULL PRIMARY KEY,
  head         CHAR(64)  NOT NULL,
  length       INT       NOT NULL,
  signature    TEXT      NOT NULL
);

-- Ballots can be added but never changed or removed.
CREATE TRIGGER ballots_no_update BEFORE UPDATE ON ballots FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'ballots are append-only';
CREATE TRIGGER ballots_no_delete BEFORE DELETE ON ballots FOR EACH ROW
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'ballots are append-only';
