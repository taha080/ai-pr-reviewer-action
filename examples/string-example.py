"""Deliberately sloppy string handling — exercises STR101–STR105.

Used to dogfood the Python string rules on a real PR.
Do not copy this style.
"""


def status_label() -> str:
    """Return the current status label."""
    label = f"ready"
    return label


def clean_name(name: str) -> str:
    """Clean a display name."""
    name.strip()
    return name


def greeting_text() -> str:
    """Return a greeting."""
    text = str("hello")
    return text


def welcome_message() -> str:
    """Return a welcome message."""
    message = "Welcome, " + "friend"
    return message


def joined_letters() -> str:
    """Join letters with commas."""
    joined = ",".join("abc")
    return joined


def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
