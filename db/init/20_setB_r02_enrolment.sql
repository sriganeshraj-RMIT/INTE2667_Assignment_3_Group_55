-- R2 - Verified enrolment and address changes (Set B, Akash). Runs after 20_setB_electors.sql.
USE identity_db;

-- MOCK official identity source. In the real system this is a call to the government's Document
-- Verification Service, which answers only "match" or "no match". It is NOT part of our roll: our own
-- tables never hold a document number, only its keyed hash (R9).
CREATE TABLE identity_records (
  id           CHAR(36)     NOT NULL PRIMARY KEY,
  given_name   VARCHAR(100) NOT NULL,
  family_name  VARCHAR(100) NOT NULL,
  dob          DATE         NOT NULL,
  doc_type     VARCHAR(20)  NOT NULL,
  doc_number   VARCHAR(20)  NOT NULL,
  citizen      BOOLEAN      NOT NULL,
  UNIQUE KEY uq_identity_doc (doc_type, doc_number)
);

INSERT INTO identity_records (id, given_name, family_name, dob, doc_type, doc_number, citizen) VALUES
  (UUID(), 'Alex',   'Citizen', '1990-04-12', 'PASSPORT',       'PA1234567', TRUE),
  (UUID(), 'Taylor', 'Morgan',  '1995-02-17', 'DRIVER_LICENCE', 'DL7654321', TRUE),
  (UUID(), 'Casey',  'Lee',     '2003-11-02', 'PASSPORT',       'PB2468135', TRUE),
  (UUID(), 'Robin',  'Visitor', '1988-06-09', 'PASSPORT',       'PX9999999', FALSE);

-- Which electoral division each postcode belongs to (a small sample for the prototype).
CREATE TABLE postcode_divisions (
  postcode  CHAR(4)      NOT NULL PRIMARY KEY,
  division  VARCHAR(100) NOT NULL,
  state     VARCHAR(50)  NOT NULL
);

INSERT INTO postcode_divisions (postcode, division, state) VALUES
  ('3000', 'Melbourne', 'VIC'), ('3053', 'Melbourne', 'VIC'), ('3065', 'Melbourne', 'VIC'),
  ('3181', 'Macnamara', 'VIC'), ('3182', 'Macnamara', 'VIC'), ('2000', 'Sydney', 'NSW');

-- The roll keeps only a keyed hash of the identity document (R9), unique so nobody is enrolled twice,
-- and the voter account (if any) that may change this enrolment's address.
ALTER TABLE electors
  ADD COLUMN doc_hash   CHAR(64) NULL,
  ADD COLUMN account_id CHAR(36) NULL,
  ADD UNIQUE KEY uq_electors_doc (doc_hash);

-- Single-use codes "posted" to an address. Only a keyed hash of the code is stored.
CREATE TABLE enrolment_codes (
  id                CHAR(36)     NOT NULL PRIMARY KEY,
  elector_id        CHAR(36)     NOT NULL,
  purpose           ENUM('ENROL','ADDRESS') NOT NULL,
  code_hash         CHAR(64)     NOT NULL,
  new_address_line  VARCHAR(200),
  new_suburb        VARCHAR(100),
  new_postcode      CHAR(4),
  new_state         VARCHAR(50),
  new_division      VARCHAR(100),
  expires_at        DATETIME     NOT NULL,
  attempts          INT          NOT NULL DEFAULT 0,
  used_at           DATETIME     NULL,
  INDEX ix_codes_elector (elector_id)
);

-- Demo: the seed voter account (01_identity.sql) can change the address of the seed elector Alex Citizen.
UPDATE electors SET account_id = (SELECT id FROM accounts WHERE email = 'voter@evp.test')
  WHERE given_name = 'Alex' AND family_name = 'Citizen';
-- The account carries the same division and state as the roll (current_user() and R3 read them from accounts).
UPDATE accounts SET division = 'Melbourne', state = 'VIC' WHERE email = 'voter@evp.test';
