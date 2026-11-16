"""Deliberately bad Python fixture — exercises SEC101–SEC105.

Used to dogfood the Python security rules on a real PR.
Do not copy this style.
"""

import os
import random
import string
import subprocess
import tempfile


def run_command(directory):
    subprocess.run(f"ls {directory}")
    subprocess.run("ls -la")


def read_file(filename):
    return os.popen(f"cat {filename}").read()


def generate_token():
    token = random.choice(string.ascii_letters)
    return token


def check_user(user):
    assert user is not None, "user required"
    return user


def make_temp():
    return tempfile.mktemp()


def share_file(path):
    os.chmod(path, 0o777)
    return path
