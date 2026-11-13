"""Deliberately bad Python fixture — exercises NAM001–NAM004.

Used to dogfood the Python naming rules on a real PR.
Do not copy this style.
"""

MaxRetries = 3
TIMEOUT = 30


def GetUserData(userId):
    return {"id": userId}


class user_record:
    pass


def process(list, type):
    return [item for item in list if item]
