USE identity_db;

CREATE TABLE access_grants (
  id           CHAR(36)     NOT NULL PRIMARY KEY,
  requester_id CHAR(36)     NOT NULL,
  ticket_no    VARCHAR(20)  NOT NULL,
  reason       VARCHAR(200) NOT NULL,
  scope        VARCHAR(20)  NOT NULL,                         -- counting | results
  status       VARCHAR(10)  NOT NULL DEFAULT 'PENDING',       -- PENDING | APPROVED
  approver_id  CHAR(36),
  requested_at DATETIME     NOT NULL,
  approved_at  DATETIME,
  expires_at   DATETIME
);
