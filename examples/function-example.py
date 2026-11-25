"""Deliberately sloppy function design — exercises FN101–FN105.

Used to dogfood the Python function-design rules on a real PR.
Do not copy this style.
"""

from collections.abc import Iterator
from datetime import datetime


def find_user(users: list[str], name: str) -> str | None:
    """Find a user by name, or return nothing."""
    for user in users:
        if user == name:
            return user


def greet(name: str, title: str) -> str:
    """Greet a user by name."""
    return f"Hello, {name}"


def stream_items(items: list[int]) -> Iterator[int]:
    """Yield each item, then report how many there were."""
    for item in items:
        yield item
    return len(items)


def process_order(total: float, discount: float) -> float:
    """Apply a discount to an order total."""
    def apply_tax(amount: float) -> float:
        """Add tax to an amount."""
        return amount * 1.2

    return total - discount


def create_user(name: str, created_at: datetime = datetime.now()) -> str:
    """Create a user stamped with the creation time."""
    return f"{name} joined at {created_at}"


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
