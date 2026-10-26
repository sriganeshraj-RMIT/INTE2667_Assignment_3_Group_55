"""R18 - ballot formality rules, written once and tested once.

Ballots are sealed (R5), so the server cannot read them on arrival. These pure functions are used
twice: by the voter's screen before the ballot is encrypted, and by the count (R7) after it is
decrypted. Each returns (formal, reason). `reason` is None for a formal ballot, otherwise one of:
UNKNOWN_CHOICE, NOT_A_NUMBER, DUPLICATE_PREFERENCE, GAP_IN_SEQUENCE, TOO_FEW_PREFERENCES,
BOTH_SECTIONS_USED, EMPTY, MALFORMED.

These are simplified versions of the AEC rules (see the constants below). They are intentionally
strict: a ballot that is doubtful is informal and the reason is recorded.
"""
SENATE_MIN_ABOVE = 1      # above the line: at least 1 box numbered (AEC savings rule)
SENATE_MIN_BELOW = 6      # below the line: at least 6 candidates numbered (AEC savings rule)


def _sequence(marks, valid_ids, minimum):
    """marks: {id: number}. The numbers used must be 1, 2, 3 ... with no repeats and no gaps."""
    if any(key not in valid_ids for key in marks):
        return False, "UNKNOWN_CHOICE"
    numbers = list(marks.values())
    if any(isinstance(n, bool) or not isinstance(n, int) for n in numbers):
        return False, "NOT_A_NUMBER"
    if len(set(numbers)) != len(numbers):
        return False, "DUPLICATE_PREFERENCE"
    if sorted(numbers) != list(range(1, len(numbers) + 1)):
        return False, "GAP_IN_SEQUENCE"
    if len(numbers) < minimum:
        return False, "TOO_FEW_PREFERENCES"
    return True, None


def _marked(section):
    return {k: v for k, v in section.items() if v is not None}


def check_house_ballot(preferences, candidate_ids):
    """House of Representatives: number every candidate 1..N, or all but one (the last is implied)."""
    if not isinstance(preferences, dict):
        return False, "MALFORMED"
    candidates = set(candidate_ids)
    return _sequence(_marked(preferences), candidates, max(len(candidates) - 1, 1))


def check_senate_ballot(above, below, group_ids, candidate_ids):
    """Senate: use ONE section only. Above the line numbers groups, below the line numbers candidates."""
    if not isinstance(above or {}, dict) or not isinstance(below or {}, dict):
        return False, "MALFORMED"
    a, b = _marked(above or {}), _marked(below or {})
    if a and b:
        return False, "BOTH_SECTIONS_USED"
    if not a and not b:
        return False, "EMPTY"
    if a:
        return _sequence(a, set(group_ids), SENATE_MIN_ABOVE)
    return _sequence(b, set(candidate_ids), SENATE_MIN_BELOW)
