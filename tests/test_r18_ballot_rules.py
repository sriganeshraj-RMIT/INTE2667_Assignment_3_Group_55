"""R18 - ballot formality rules."""
import pytest

from app.common.ballot_rules import check_house_ballot, check_senate_ballot

CANDS = ["a", "b", "c", "d"]
GROUPS = ["g1", "g2", "g3"]
BTL = [f"c{i}" for i in range(1, 13)]


def test_house_all_numbered_is_formal():
    assert check_house_ballot({"a": 2, "b": 1, "c": 4, "d": 3}, CANDS) == (True, None)


def test_house_one_square_left_blank_is_formal():
    assert check_house_ballot({"a": 1, "b": 2, "c": 3, "d": None}, CANDS) == (True, None)


@pytest.mark.parametrize("prefs, reason", [
    ({"a": 1, "b": 1, "c": 2, "d": 3}, "DUPLICATE_PREFERENCE"),
    ({"a": 1, "b": 2, "c": 4, "d": 5}, "GAP_IN_SEQUENCE"),
    ({"a": 2, "b": 3, "c": 4, "d": 5}, "GAP_IN_SEQUENCE"),
    ({"a": 1, "b": 2, "c": None, "d": None}, "TOO_FEW_PREFERENCES"),
    ({"a": 1, "b": 2, "c": 3, "zz": 4}, "UNKNOWN_CHOICE"),
    ({"a": 1, "b": "2", "c": 3, "d": 4}, "NOT_A_NUMBER"),
    ({"a": 1.5, "b": 2, "c": 3, "d": 4}, "NOT_A_NUMBER"),
    ({"a": True, "b": 2, "c": 3, "d": 4}, "NOT_A_NUMBER"),
    ({"a": 0, "b": 1, "c": 2, "d": 3}, "GAP_IN_SEQUENCE"),
    ({"a": -1, "b": 1, "c": 2, "d": 3}, "GAP_IN_SEQUENCE"),
    ({}, "TOO_FEW_PREFERENCES"),
])
def test_house_informal(prefs, reason):
    assert check_house_ballot(prefs, CANDS) == (False, reason)


def test_house_not_a_mapping():
    assert check_house_ballot([1, 2, 3], CANDS) == (False, "MALFORMED")


def test_senate_above_the_line():
    assert check_senate_ballot({"g2": 1}, {}, GROUPS, BTL) == (True, None)
    assert check_senate_ballot({"g1": 2, "g2": 1, "g3": 3}, None, GROUPS, BTL) == (True, None)


def test_senate_below_the_line_needs_six():
    assert check_senate_ballot({}, {f"c{i}": i for i in range(1, 7)}, GROUPS, BTL) == (True, None)
    assert check_senate_ballot({}, {f"c{i}": i for i in range(1, 6)}, GROUPS, BTL) == (False, "TOO_FEW_PREFERENCES")


def test_senate_both_sections_or_neither():
    assert check_senate_ballot({"g1": 1}, {"c1": 1}, GROUPS, BTL) == (False, "BOTH_SECTIONS_USED")
    assert check_senate_ballot({}, {}, GROUPS, BTL) == (False, "EMPTY")
    assert check_senate_ballot({"g1": None}, {"c1": None}, GROUPS, BTL) == (False, "EMPTY")


def test_senate_repeated_or_missing_numbers():
    assert check_senate_ballot({"g1": 1, "g2": 1}, {}, GROUPS, BTL) == (False, "DUPLICATE_PREFERENCE")
    assert check_senate_ballot({"g1": 1, "g2": 3}, {}, GROUPS, BTL) == (False, "GAP_IN_SEQUENCE")
    assert check_senate_ballot({"nope": 1}, {}, GROUPS, BTL) == (False, "UNKNOWN_CHOICE")
