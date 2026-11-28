"""Deliberately sloppy dictionary handling — exercises DCT101–DCT105.

Used to dogfood the Python dictionary rules on a real PR.
Do not copy this style.
"""


def setting_or_zero(settings: dict[str, int], key: str) -> int:
    """Return the setting for the key, or zero."""
    return settings[key] if key in settings else 0


def lookup_or_default(settings: dict[str, int], key: str) -> int:
    """Return the setting for the key, or zero."""
    if key in settings:
        value = settings[key]
    else:
        value = 0
    return value


def ensure_count(counts: dict[str, int], key: str) -> int:
    """Return the count for the key, starting at zero."""
    if key not in counts:
        counts[key] = 0
    return counts[key]


def empty_settings() -> dict[str, int]:
    """Return an empty settings dict."""
    settings = dict()
    return settings


def bump_count(counts: dict[str, int], key: str) -> int:
    """Add one to the count for the key and return it."""
    counts[key] = counts[key] + 1
    return counts[key]


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
