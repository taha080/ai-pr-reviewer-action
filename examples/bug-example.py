"""Deliberately bad Python fixture — exercises BUG101–BUG105.

Used to dogfood the Python bug rules on a real PR.
Do not copy this style.
"""


def unreachable_after_return(user):
    if not user:
        return None
    return user
    log_audit(user)


def load_or_fail(path):
    if not path:
        raise ValueError("path required")
        fallback_load(path)
    return open(path)


def default_settings():
    return {"theme": "dark", "retries": 3, "theme": "light"}


def check_status(code):
    if code is 200:
        return "ok"
    if code is "404":
        return "missing"
    return "other"


def feature_enabled():
    if True:
        return True
    return False


def drain_queue(queue):
    while False:
        process(queue.pop())
    return queue


def same_user(current, other):
    if current == current:
        return True
    return current == other
