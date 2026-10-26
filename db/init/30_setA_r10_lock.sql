-- R10 - once an election is locked (status is no longer DRAFT), its candidates, party order and times
-- cannot be changed, and its status only moves forward (APPROVED -> OPEN -> CLOSED).
USE identity_db;

DELIMITER $$

CREATE TRIGGER candidates_locked_insert BEFORE INSERT ON candidates FOR EACH ROW
BEGIN
  IF (SELECT status FROM elections WHERE id = NEW.election_id) <> 'DRAFT' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'election is locked: candidates cannot be changed';
  END IF;
END$$

CREATE TRIGGER candidates_locked_update BEFORE UPDATE ON candidates FOR EACH ROW
BEGIN
  IF (SELECT status FROM elections WHERE id = OLD.election_id) <> 'DRAFT'
     OR (SELECT status FROM elections WHERE id = NEW.election_id) <> 'DRAFT' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'election is locked: candidates cannot be changed';
  END IF;
END$$

CREATE TRIGGER candidates_locked_delete BEFORE DELETE ON candidates FOR EACH ROW
BEGIN
  IF (SELECT status FROM elections WHERE id = OLD.election_id) <> 'DRAFT' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'election is locked: candidates cannot be changed';
  END IF;
END$$

CREATE TRIGGER elections_locked_update BEFORE UPDATE ON elections FOR EACH ROW
BEGIN
  IF OLD.status <> 'DRAFT' AND (
       NEW.name <> OLD.name OR NEW.division <> OLD.division OR NEW.state <> OLD.state
       OR NEW.opens_at <> OLD.opens_at OR NEW.closes_at <> OLD.closes_at
       OR NOT (NEW.definition_fp <=> OLD.definition_fp) OR NOT (NEW.definition_sig <=> OLD.definition_sig)
       OR NEW.status = 'DRAFT'
       OR (OLD.status = 'OPEN' AND NEW.status = 'APPROVED')
       OR (OLD.status = 'CLOSED' AND NEW.status <> 'CLOSED')) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'election is locked';
  END IF;
END$$

CREATE TRIGGER elections_locked_delete BEFORE DELETE ON elections FOR EACH ROW
BEGIN
  IF OLD.status <> 'DRAFT' THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'election is locked';
  END IF;
END$$

DELIMITER ;
