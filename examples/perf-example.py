"""Deliberately slow Python fixture — exercises PERF101–PERF105.

Used to dogfood the Python performance rules on a real PR.
Do not copy this style.
"""


def build_message(parts):
    message = ""
    for part in parts:
        message += part
    return message


def show_indexes(items):
    total = 0
    for i in range(len(items)):
        total += items[i]
    return total


def is_allowed(name):
    return name in ["alice", "bob", "carol"]


def squares(numbers):
    result = []
    for n in numbers:
        result.append(n * n)
    return result


def show_keys(config):
    count = 0
    for key in config.keys():
        count += 1
    return count
