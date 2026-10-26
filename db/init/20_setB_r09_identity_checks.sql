-- R9 - Identity-document minimisation (Set B, Akash). Runs after 20_setB_r02_enrolment.sql.
USE identity_db;

-- Every identity check made by R2 (enrolment and address change): the scrambled document, the result and a
-- reference. Never the document number, never an image, never a name or address.
CREATE TABLE identity_checks (
  id          CHAR(36)    NOT NULL PRIMARY KEY,         -- the reference
  doc_type    VARCHAR(20) NOT NULL,
  doc_hash    CHAR(64)    NOT NULL,                     -- keyed hash (HMAC-SHA256) of the document number
  result      ENUM('MATCH','NO_MATCH') NOT NULL,
  purpose     ENUM('ENROL','ADDRESS')  NOT NULL,
  elector_id  CHAR(36)    NULL,                         -- filled in once an enrolment exists
  checked_by  VARCHAR(36) NOT NULL,                     -- officer or voter account, or 'anonymous'
  checked_at  DATETIME    NOT NULL,
  INDEX ix_identity_checks_doc (doc_hash)
);
