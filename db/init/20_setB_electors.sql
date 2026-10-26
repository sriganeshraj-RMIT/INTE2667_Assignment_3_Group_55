-- Set B (Akash) - the electoral roll. Runs after 01_identity.sql.
-- Created for R15 (no harvesting of the voter list); R2 (verified enrolment) adds to it later.
USE identity_db;

CREATE TABLE electors (
  id            CHAR(36)     NOT NULL PRIMARY KEY,
  given_name    VARCHAR(100) NOT NULL,
  family_name   VARCHAR(100) NOT NULL,
  dob           DATE         NOT NULL,
  address_line  VARCHAR(200) NOT NULL,
  suburb        VARCHAR(100) NOT NULL,
  postcode      CHAR(4)      NOT NULL,
  state         VARCHAR(50)  NOT NULL,
  division      VARCHAR(100) NOT NULL,
  email         VARCHAR(255),
  status        ENUM('PENDING','ENROLLED') NOT NULL DEFAULT 'PENDING',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX ix_electors_lookup (family_name, given_name, dob, postcode),
  INDEX ix_electors_search (division, family_name, postcode)
);

-- Made-up test electors so the R15 check and search can be demonstrated.
INSERT INTO electors (id, given_name, family_name, dob, address_line, suburb, postcode, state, division, email, status) VALUES
  (UUID(), 'Alex',   'Citizen', '1990-04-12', '1 Swanston St',  'Melbourne',    '3000', 'VIC', 'Melbourne', 'alex.citizen@evp.test', 'ENROLLED'),
  (UUID(), 'Sam',    'Citizen', '1985-09-30', '22 Lygon St',    'Carlton',      '3053', 'VIC', 'Melbourne', 'sam.citizen@evp.test',  'ENROLLED'),
  (UUID(), 'Jordan', 'Nguyen',  '2001-01-05', '5 Smith St',     'Fitzroy',      '3065', 'VIC', 'Melbourne', 'jordan.nguyen@evp.test','ENROLLED'),
  (UUID(), 'Riley',  'Patel',   '1978-07-21', '80 Chapel St',   'Prahran',      '3181', 'VIC', 'Macnamara', 'riley.patel@evp.test',  'ENROLLED');

-- The seed officer (01_identity.sql) has no division, and R15 refuses voter-list searches from staff
-- without one (deny by default). Give the test officer a division so the search can be demonstrated.
UPDATE accounts SET division = 'Melbourne', state = 'VIC' WHERE email = 'officer@evp.test';
