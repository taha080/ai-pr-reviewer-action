"""Deliberately bad Python fixture — exercises IMP001–IMP003.

Used to dogfood the Python import rules on a real PR.
Do not copy this style.
"""

from helpers import *
import os
import json


def load_config(path):
    import yaml
    return yaml.safe_load(open(path))


def dump(data):
    return json.dumps(data)
