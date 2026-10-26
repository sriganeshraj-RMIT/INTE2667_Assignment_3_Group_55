CREATE DATABASE IF NOT EXISTS identity_db;
USE identity_db;

CREATE TABLE accounts (
  id            CHAR(36)      NOT NULL PRIMARY KEY,
  email         VARCHAR(255)  NOT NULL UNIQUE,
  password_hash VARCHAR(255)  NOT NULL,
  role          ENUM('voter','officer','delegate','counting_officer','auditor','custodian','admin') NOT NULL,
  division      VARCHAR(100),
  state         VARCHAR(50),
  mfa_secret_enc VARCHAR(512),
  status        ENUM('PENDING','ACTIVE','SUSPENDED','DISABLED') NOT NULL DEFAULT 'PENDING',
  contract_end  DATE,
  last_login    DATETIME,
  created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- one seed account per role so your teammates can log in immediately
INSERT INTO accounts (id, email, password_hash, role, status) VALUES
  (UUID(), 'voter@evp.test',   '$argon2id$placeholder', 'voter',           'ACTIVE'),
  (UUID(), 'officer@evp.test', '$argon2id$placeholder', 'officer',         'ACTIVE'),
  (UUID(), 'delegate@evp.test','$argon2id$placeholder', 'delegate',        'ACTIVE'),
  (UUID(), 'counter@evp.test', '$argon2id$placeholder', 'counting_officer','ACTIVE'),
  (UUID(), 'auditor@evp.test', '$argon2id$placeholder', 'auditor',         'ACTIVE'),
  (UUID(), 'custodian@evp.test','$argon2id$placeholder','custodian',       'ACTIVE'),
  (UUID(), 'admin@evp.test',   '$argon2id$placeholder', 'admin',           'ACTIVE');