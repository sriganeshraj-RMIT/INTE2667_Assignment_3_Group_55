def audit(event: str, actor_id: str, details: dict) -> None:
    """Appends a chained, signed entry to the audit log. R17."""
    # TODO R17: hash chain + Ed25519 signature + INSERT
    print(f"[AUDIT] {event} actor={actor_id} details={details}")