# Dogfood fixture for the comment-marker feature (Day 10).
# Deliberately flagged code so the dogfood run (marker "dogfood") and the
# released v1.2 example run (default marker) each post their own comment:
# - trailing whitespace below triggers STY003 (both runs flag it)
# - print() triggers STY002 (dogfood ignores it via ignore-rules, so only
#   the example run flags it — proving the two comments are independent)
# - a new source file with no test touched triggers TST001 (both runs)

value = 41   
print("marker fixture:", value)
