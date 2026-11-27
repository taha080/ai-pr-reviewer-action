"""Deliberately sloppy return-value handling — exercises RET101–RET105.

Used to dogfood the Python return-value rules on a real PR.
Do not copy this style.
"""

import random


def sorted_items(items: list[int]) -> list[int]:
    """Return the items in sorted order."""
    result = items.sort()
    return result


def with_extra(items: list[int], extra: int) -> list[int]:
    """Return the items with one extra value added."""
    result = items.append(extra)
    return result


def merged_settings(settings: dict[str, int], extra: dict[str, int]) -> dict[str, int]:
    """Return the settings merged with the extras."""
    result = settings.update(extra)
    return result


def shuffled_items(items: list[int]) -> list[int]:
    """Return the items in a random order."""
    result = random.shuffle(items)
    return result


def with_tag(tags: set[str], tag: str) -> set[str]:
    """Return the tags with one more tag added."""
    result = tags.add(tag)
    return result


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
