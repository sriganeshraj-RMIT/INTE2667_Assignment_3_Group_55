-- R1 - Voting anonymously (Set B, Akash).

-- ISSUER side (identity_db): one RSA key per election for blind-signing voting passes.
-- The private key is stored encrypted; the checker only ever reads n and e.
USE identity_db;
CREATE TABLE pass_keys (
  election_id   CHAR(36) NOT NULL PRIMARY KEY,
  n_hex         TEXT     NOT NULL,
  e             INT      NOT NULL,
  private_enc   TEXT     NOT NULL,
  created_at    DATETIME NOT NULL
);

-- CHECKER side (ballot_db): passes that have been used. Only a hash of the pass and the election:
-- no voter, no account, no time, no IP, so a used pass cannot be traced back to anyone.
USE ballot_db;
CREATE TABLE spent_passes (
  token_hash   CHAR(64) NOT NULL PRIMARY KEY,
  election_id  CHAR(36) NOT NULL
);
