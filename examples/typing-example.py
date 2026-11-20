"""Typing examples for the dogfood run."""

from typing import Any, Dict, List


def fetch_user(user_id: int):
    """Fetch a user by id."""
    return {"id": user_id}


def greet(name, greeting: str = "Hello") -> str:
    """Greet someone by name."""
    return f"{greeting} {name}"


def load_config(path: str) -> Any:
    """Load the config file."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def collect_names(users: List[str]) -> dict:
    """Count names in the list."""
    counts: Dict[str, int] = {}
    for user in users:
        counts[user] = counts.get(user, 0) + 1
    return counts


def save_record(record: dict) -> None:
    """Save a record to the store."""
    return record
