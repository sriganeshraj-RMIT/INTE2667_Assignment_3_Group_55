from flask import abort, jsonify

def validate(schema: dict, payload: dict) -> dict:
    """
    Checks payload against schema allow-list. Raises HTTP 400 on failure. R18.
    schema format: {"field_name": {"type": str, "max_length": 100, "required": True}}
    """
    errors = []
    for field, rules in schema.items():
        value = payload.get(field)
        if rules.get("required") and value is None:
            errors.append(f"{field} is required")
            continue
        if value is not None and rules.get("type") and not isinstance(value, rules["type"]):
            errors.append(f"{field} must be {rules['type'].__name__}")
        if value and rules.get("max_length") and len(str(value)) > rules["max_length"]:
            errors.append(f"{field} exceeds max length {rules['max_length']}")
    if errors:
        abort(400, description={"error": "VALIDATION_FAILED", "message": errors})
    return payload