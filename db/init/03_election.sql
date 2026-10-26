USE identity_db;

CREATE TABLE elections (
  id            CHAR(36)     NOT NULL PRIMARY KEY,
  name          VARCHAR(255) NOT NULL,
  division      VARCHAR(100) NOT NULL,
  state         VARCHAR(50)  NOT NULL,
  opens_at      DATETIME     NOT NULL,
  closes_at     DATETIME     NOT NULL,
  definition_fp CHAR(64),
  definition_sig TEXT,
  status        ENUM('DRAFT','APPROVED','OPEN','CLOSED') NOT NULL DEFAULT 'DRAFT',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE candidates (
  id          CHAR(36)     NOT NULL PRIMARY KEY,
  election_id CHAR(36)     NOT NULL,
  name        VARCHAR(255) NOT NULL,
  party       VARCHAR(255),
  ballot_pos  INT          NOT NULL,
  FOREIGN KEY (election_id) REFERENCES elections(id)
);

-- seed: one small election with 5 candidates across 2 divisions
INSERT INTO elections (id, name, division, state, opens_at, closes_at, status) VALUES
  ('aaaa-0001', 'Test Election 2026', 'Melbourne', 'VIC',
   '2026-11-01 08:00:00', '2026-11-01 18:00:00', 'DRAFT'),
  ('aaaa-0002', 'Test Election 2026', 'Sydney',    'NSW',
   '2026-11-01 08:00:00', '2026-11-01 18:00:00', 'DRAFT');

INSERT INTO candidates (id, election_id, name, party, ballot_pos) VALUES
  (UUID(), 'aaaa-0001', 'Alice Smith',   'Party A', 1),
  (UUID(), 'aaaa-0001', 'Bob Jones',     'Party B', 2),
  (UUID(), 'aaaa-0001', 'Carol White',   'Party C', 3),
  (UUID(), 'aaaa-0002', 'David Brown',   'Party A', 1),
  (UUID(), 'aaaa-0002', 'Eve Taylor',    'Party B', 2);