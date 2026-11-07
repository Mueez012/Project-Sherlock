"""Ownership policy without dependencies on identity credentials or storage."""

from .errors import AccessDenied


def valid_actor_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and not any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def require_owner(actor_id: str, owner_id: str) -> None:
    """Require an explicit, valid principal matching the saved owner exactly."""
    if not valid_actor_id(actor_id) or not valid_actor_id(owner_id) or actor_id != owner_id:
        raise AccessDenied()
