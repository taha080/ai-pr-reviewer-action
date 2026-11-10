"""Deliberately bad Python fixture — exercises CPL004–CPL007.

Used to dogfood the Python complexity/quality rules on a real PR.
Do not copy this style.
"""


def route_request(mode, verbose=True, dry_run=False):
    if mode == "a":
        return 1
    if mode == "b":
        return 2
    if mode == "c":
        return 3
    if mode == "d":
        return 4
    if mode == "e":
        return 5
    if mode == "f":
        return 6
    return 0


def nested_grid(rows):
    return [[x * y for y in row] for row in rows for x in row]


double = lambda n: n * 2
