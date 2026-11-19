"""Deliberately undocumented Python fixture — exercises DOC101–DOC105.

Used to dogfood the Python documentation rules on a real PR.
Do not copy this style.
"""


def fetch_user(user_id):
    return {"id": user_id}


def greet(name):
    """Say hello"""
    return f"Hello {name}"


class UserRecord:
    def __init__(self, name):
        self.name = name


def empty_doc():
    """"""
    return None


def stale_note():
    """Fetch the record. TODO: handle the missing case."""
    return None
