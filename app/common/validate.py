"""R18 - strict, server-side input checks (allow-list).

Every endpoint describes what it accepts in a SCHEMA and passes the request body through
validate(). Anything that is not described is refused, so wrong or harmful data is rejected
before it reaches the database or the count.

    SCHEMA = {
        "postcode": {"type": str, "pattern": r"\\d{4}", "required": True},
        "age":      {"type": int, "min": 0, "max": 120},
        "role":     {"type": str, "allowed": ["voter", "officer"]},
    }
    data = validate(SCHEMA, request.get_json(silent=True))

Rules a field can have:
    type        str, int, float, bool, list or dict (default str)
    required    True if the field must be present
    default     value used when an optional field is missing
    nullable    not needed: null is treated the same as "missing"
    str:        min_length, max_length (default cap 1000), pattern (whole value must match),
                allowed (list of exact values), strip (default True), allow_markup (default False)
    int/float:  min, max
    list:       items (rules for each item), min_items, max_items (default cap 100)
    dict:       fields (a nested schema)

A failed check raises ValidationError (HTTP 400). The error handler in common/security.py turns it
into the team's JSON: {"error": "VALIDATION_FAILED", "message": "..."}. The message never repeats
what the user sent.
"""
import json
import math
import re
import unicodedata

from werkzeug.exceptions import BadRequest
from werkzeug.utils import secure_filename

DEFAULT_MAX_LENGTH = 1000
DEFAULT_MAX_ITEMS = 100
MAX_DEPTH = 4

# Defence in depth: even when a pattern is not given, text never carries control characters or
# things that look like HTML, script, event handlers or template code.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MARKUP = re.compile(r"<\s*/?\s*[a-z!?]|javascript\s*:|\bon[a-z]+\s*=|\{\{|\{%|\$\{", re.IGNORECASE)

_BAD = object()


class ValidationError(BadRequest):
    """HTTP 400 carrying a list of plain-text problems (field names come from the schema, not the user)."""

    error_code = "VALIDATION_FAILED"

    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__(description="; ".join(self.problems))


def _type_ok(value, expected):
    if expected is bool:
        return isinstance(value, bool)
    if isinstance(value, bool):                 # True/False must not pass as numbers
        return False
    if expected is float:
        return isinstance(value, (int, float))
    return isinstance(value, expected)


def _check(name, value, rules, problems, depth):
    expected = rules.get("type", str)
    if not _type_ok(value, expected):
        problems.append(f"{name} must be {expected.__name__}")
        return _BAD

    if expected is str:
        value = unicodedata.normalize("NFC", value)
        if rules.get("strip", True):
            value = value.strip()
        if _CONTROL.search(value):
            problems.append(f"{name} contains characters that are not allowed")
            return _BAD
        if not rules.get("allow_markup", False) and _MARKUP.search(value):
            problems.append(f"{name} contains characters that are not allowed")
            return _BAD
        min_len = rules.get("min_length", 1 if rules.get("required") else 0)
        max_len = rules.get("max_length", DEFAULT_MAX_LENGTH)
        if len(value) < min_len:
            problems.append(f"{name} is too short" if value else f"{name} is required")
            return _BAD
        if len(value) > max_len:
            problems.append(f"{name} is too long (maximum {max_len})")
            return _BAD
        if "pattern" in rules and not re.fullmatch(rules["pattern"], value):
            problems.append(f"{name} has the wrong format")
            return _BAD
        if "allowed" in rules and value not in rules["allowed"]:
            problems.append(f"{name} is not one of the allowed values")
            return _BAD
        return value

    if expected in (int, float):
        if isinstance(value, float) and not math.isfinite(value):
            problems.append(f"{name} must be a finite number")
            return _BAD
        if "min" in rules and value < rules["min"]:
            problems.append(f"{name} must be at least {rules['min']}")
            return _BAD
        if "max" in rules and value > rules["max"]:
            problems.append(f"{name} must be at most {rules['max']}")
            return _BAD
        if "allowed" in rules and value not in rules["allowed"]:
            problems.append(f"{name} is not one of the allowed values")
            return _BAD
        return value

    if expected is list:
        if len(value) > rules.get("max_items", DEFAULT_MAX_ITEMS):
            problems.append(f"{name} has too many items")
            return _BAD
        if len(value) < rules.get("min_items", 0):
            problems.append(f"{name} has too few items")
            return _BAD
        item_rules = rules.get("items")
        if item_rules is None:
            problems.append(f"{name} must describe its items in the schema")
            return _BAD
        cleaned = []
        for i, item in enumerate(value):
            got = _check(f"{name}[{i}]", item, item_rules, problems, depth + 1)
            if got is not _BAD:
                cleaned.append(got)
        return cleaned if len(cleaned) == len(value) else _BAD

    if expected is dict:
        if depth >= MAX_DEPTH or "fields" not in rules:
            problems.append(f"{name} is not allowed")
            return _BAD
        return _validate_dict(name, value, rules["fields"], problems, depth + 1)

    return value                                  # bool


def _validate_dict(prefix, payload, schema, problems, depth):
    clean = {}
    if any(key not in schema for key in payload):
        problems.append(f"{prefix + ': ' if prefix else ''}request contains fields that are not allowed")
    for field, rules in schema.items():
        label = f"{prefix}.{field}" if prefix else field
        value = payload.get(field)
        if value is None:
            if rules.get("required"):
                problems.append(f"{label} is required")
            elif "default" in rules:
                clean[field] = rules["default"]
            continue
        got = _check(label, value, rules, problems, depth)
        if got is not _BAD:
            clean[field] = got
    return clean


def validate(schema: dict, payload) -> dict:
    """Check payload against schema. Returns a clean dict, or raises ValidationError (HTTP 400)."""
    if not isinstance(payload, dict):
        raise ValidationError(["request body must be a JSON object"])
    problems = []
    clean = _validate_dict("", payload, schema, problems, 0)
    if problems:
        raise ValidationError(problems)
    return clean


# ------------------------------------------------------------------ uploaded files
_SIGNATURES = {"png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff", "pdf": b"%PDF-"}
SUPPORTED_UPLOADS = ("json", "csv", "png", "jpg", "pdf")


def validate_upload(file, allowed=SUPPORTED_UPLOADS, max_bytes=2_000_000):
    """Check an uploaded file (werkzeug FileStorage). Returns (safe_filename, content_bytes).

    Checks the name, the extension against an allow-list, the size, and that the content really
    is what the extension says (file signature for images and PDFs, parseable text for JSON/CSV).
    """
    if file is None or not getattr(file, "filename", ""):
        raise ValidationError(["a file is required"])
    name = secure_filename(file.filename)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    ext = "jpg" if ext == "jpeg" else ext
    if ext not in allowed or ext not in SUPPORTED_UPLOADS:
        raise ValidationError(["this file type is not allowed"])
    data = file.read(max_bytes + 1)
    if not data:
        raise ValidationError(["the file is empty"])
    if len(data) > max_bytes:
        raise ValidationError(["the file is too large"])
    if ext in _SIGNATURES:
        if not data.startswith(_SIGNATURES[ext]):
            raise ValidationError(["the file content does not match its type"])
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValidationError(["the file is not valid text"])
        if "\x00" in text:
            raise ValidationError(["the file is not valid text"])
        if ext == "json":
            try:
                json.loads(text)
            except ValueError:
                raise ValidationError(["the file is not valid JSON"])
    return name, data
