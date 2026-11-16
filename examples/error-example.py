"""Deliberately bad Python fixture — exercises ERR001–ERR004.

Used to dogfood the Python error-handling rules on a real PR.
Do not copy this style.
"""


def load_user(user_id):
    try:
        return fetch_user(user_id)
    except ValueError:
        pass


def convert_config(raw):
    try:
        return parse_config(raw)
    except ValueError as e:
        raise RuntimeError("bad config")


def shutdown():
    try:
        stop_server()
    except BaseException:
        cleanup()


def maybe_nothing():
    try:
        pass
    except ValueError:
        handle_error()
