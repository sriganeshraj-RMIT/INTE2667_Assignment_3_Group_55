USE identity_db;

CREATE TABLE exclusions (
  id           CHAR(36)     NOT NULL PRIMARY KEY,
  election_id  CHAR(36)     NOT NULL,
  candidate_id CHAR(36)     NOT NULL,
  reason       VARCHAR(200) NOT NULL,
  status       VARCHAR(10)  NOT NULL DEFAULT 'PENDING',      -- PENDING | APPROVED | REJECTED
  proposed_by  CHAR(36)     NOT NULL,
  approved_by  CHAR(36),
  proposed_at  DATETIME     NOT NULL,
  decided_at   DATETIME
);

-- The two-person rule needs two different delegates. 01_identity.sql only has one,
-- so add a second (same placeholder password style; the R8 owner sets real passwords).
INSERT INTO accounts (id, email, password_hash, role, status) VALUES
  (UUID(), 'delegate2@evp.test', '$argon2id$placeholder', 'delegate', 'ACTIVE');
