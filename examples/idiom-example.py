"""Deliberately unidiomatic Python — exercises IDM101–IDM105.

Used to dogfood the Python idiom rules on a real PR.
Do not copy this style.
"""


def read_first_line(path: str) -> str:
    """Read the first line of a file, leaking the handle."""
    handle = open(path)
    return handle.readline()


def read_safely(path: str) -> str:
    """Read the first line of a file, closing it properly."""
    with open(path) as handle:
        return handle.readline()


def is_text(value: object) -> bool:
    """Check whether a value is a string, the exact-type way."""
    return type(value) == str


def is_empty(items: list[str]) -> bool:
    """Check whether a list is empty, the long way."""
    return len(items) == 0


def has_items(items: list[str]) -> bool:
    """Check whether a list has anything in it, the long way."""
    return len(items) != 0


def greet(name: str) -> str:
    """Greet someone with old-style formatting."""
    return "Hello, %s!" % name


def has_key(mapping: dict[str, int], key: str) -> bool:
    """Check whether a key is present, via .keys()."""
    return key in mapping.keys()
