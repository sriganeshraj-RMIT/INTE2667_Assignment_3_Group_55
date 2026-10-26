"""R18 - validate(): the allow-list rules, with the attacks it must stop."""
import io

import pytest
from werkzeug.datastructures import FileStorage

from app.common.validate import ValidationError, validate, validate_upload

SCHEMA = {
    "name":     {"type": str, "max_length": 20, "required": True},
    "postcode": {"type": str, "pattern": r"\d{4}", "required": True},
    "age":      {"type": int, "min": 0, "max": 120},
    "role":     {"type": str, "allowed": ["voter", "officer"]},
    "tags":     {"type": list, "items": {"type": str, "max_length": 5}, "max_items": 3},
    "address":  {"type": dict, "fields": {"street": {"type": str, "max_length": 30, "required": True}}},
}
GOOD = {"name": "Alice", "postcode": "3000"}


def problems(payload, schema=SCHEMA):
    with pytest.raises(ValidationError) as e:
        validate(schema, payload)
    return e.value.problems


def test_good_input_is_returned_clean():
    assert validate(SCHEMA, dict(GOOD, name="  Alice  ", age=30)) == {"name": "Alice", "postcode": "3000", "age": 30}


def test_missing_required_field():
    assert "postcode is required" in problems({"name": "Alice"})


def test_blank_required_text_counts_as_missing():
    assert "name is required" in problems(dict(GOOD, name="   "))


def test_unknown_fields_are_refused():
    assert problems(dict(GOOD, is_admin=True)) == ["request contains fields that are not allowed"]


@pytest.mark.parametrize("body", [None, [], "text", 5, [{"name": "x"}]])
def test_body_must_be_a_json_object(body):
    assert problems(body) == ["request body must be a JSON object"]


def test_wrong_type():
    assert "age must be int" in problems(dict(GOOD, age="30"))


def test_booleans_are_not_numbers():
    assert "age must be int" in problems(dict(GOOD, age=True))


def test_number_range():
    assert problems(dict(GOOD, age=-1)) and problems(dict(GOOD, age=121))


def test_too_long():
    assert any("too long" in p for p in problems(dict(GOOD, name="x" * 21)))


def test_strings_have_a_default_length_cap():
    schema = {"note": {"type": str}}
    assert any("too long" in p for p in problems({"note": "x" * 1001}, schema))


def test_pattern_must_match_the_whole_value():
    assert problems(dict(GOOD, postcode="3000abc")) and problems(dict(GOOD, postcode="abc3000"))


def test_allowed_values_only():
    assert problems(dict(GOOD, role="admin"))


@pytest.mark.parametrize("attack", [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "javascript:alert(1)",
    "x onclick=steal()", "{{ 7*7 }}", "{% for x in y %}", "${jndi:ldap://evil}", "Bob\x00",
])
def test_code_hidden_in_a_text_field_is_refused(attack):
    assert any("not allowed" in p for p in problems(dict(GOOD, name=attack)))


def test_sql_injection_text_never_matches_a_strict_pattern():
    assert problems(dict(GOOD, postcode="3000' OR '1'='1' --"))


def test_ordinary_names_are_not_blocked():
    assert validate(SCHEMA, dict(GOOD, name="Zoe O'Brien-Lee"))["name"] == "Zoe O'Brien-Lee"


def test_lists_check_every_item_and_the_count():
    assert any("tags[1]" in p for p in problems(dict(GOOD, tags=["ok", "far too long"])))
    assert any("too many" in p for p in problems(dict(GOOD, tags=["a", "b", "c", "d"])))


def test_nested_objects_are_checked_and_extra_keys_refused():
    assert validate(SCHEMA, dict(GOOD, address={"street": "1 Main St"}))["address"] == {"street": "1 Main St"}
    assert problems(dict(GOOD, address={"street": "1 Main St", "x": 1}))
    assert problems(dict(GOOD, address={}))


def test_error_text_never_repeats_what_the_user_sent():
    for p in problems(dict(GOOD, name="<script>EVIL-MARKER</script>")):
        assert "EVIL-MARKER" not in p


def test_optional_default():
    assert validate({"n": {"type": int, "default": 5}}, {}) == {"n": 5}


# ----------------------------------------------------------------- uploads
def upload(name, data):
    return FileStorage(stream=io.BytesIO(data), filename=name)


def test_good_json_upload():
    assert validate_upload(upload("batch.json", b'{"a": 1}'))[0] == "batch.json"


def test_good_png_upload():
    assert validate_upload(upload("scan.png", b"\x89PNG\r\n\x1a\n" + b"0" * 20))[0] == "scan.png"


@pytest.mark.parametrize("name", ["run.exe", "page.html", "x.php", "noext", "a.json.exe"])
def test_file_types_outside_the_allow_list_are_refused(name):
    with pytest.raises(ValidationError):
        validate_upload(upload(name, b"{}"))


def test_png_with_the_wrong_content_is_refused():
    with pytest.raises(ValidationError):
        validate_upload(upload("scan.png", b"<html>not an image</html>"))


def test_broken_json_is_refused():
    with pytest.raises(ValidationError):
        validate_upload(upload("batch.json", b"{not json"))


def test_empty_and_oversize_files_are_refused():
    with pytest.raises(ValidationError):
        validate_upload(upload("a.json", b""))
    with pytest.raises(ValidationError):
        validate_upload(upload("a.json", b'{"a": "' + b"x" * 100 + b'"}'), max_bytes=50)


def test_path_tricks_in_the_file_name_are_removed():
    name, _ = validate_upload(upload("../../etc/passwd.json", b"{}"))
    assert "/" not in name and ".." not in name


def test_no_file():
    with pytest.raises(ValidationError):
        validate_upload(None)
