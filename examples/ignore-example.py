"""Dogfood fixture for the ignore-rules input.

Deliberately flagged code: a print() call (STY002) and a TODO marker
(BUG003). The dogfood workflow passes ignore-rules: STY002, so the
action's own review comment on the dogfood PR should flag BUG003
but NOT STY002.
"""

print("hello from the ignore-rules fixture")
# TODO: replace this with proper logging before shipping
