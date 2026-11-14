"""Deliberately bad Python fixture — exercises STY003–STY006.

Used to dogfood the Python style rules on a real PR.
Do not copy this style.
"""

value = 1   
name = "a"; count = 2


def check_flag(flag):
    if flag == None:
        return True
    if flag == False:
        return False
    return flag


def tabbed():
	return 1
