"""Tests for the ai-pr-reviewer-action rule engine and diff parser.

Run with:  python3 -m unittest discover -s tests -v
Only the standard library is used.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.checks import review_files  # noqa: E402
from src.diffparse import parse_unified_diff  # noqa: E402
from src.report import render_report, verdict  # noqa: E402


SAMPLE_DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,3 +1,8 @@
 import os
+api_key = "sk-live-123456"
+eval(user_input)
+try:
+    do_thing()
+except:
+    pass
 context = True
"""

MISSING_TESTS_DIFF = """diff --git a/service.py b/service.py
--- a/service.py
+++ b/service.py
@@ -1,1 +1,2 @@
 def helper():
+    return 42
"""


class TestDiffParse(unittest.TestCase):
    def test_added_lines_get_real_line_numbers(self):
        files = parse_unified_diff(SAMPLE_DIFF)
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].path, "app.py")
        texts = [line.text for line in files[0].added]
        self.assertIn('api_key = "sk-live-123456"', texts)
        # api_key is the first added line: new file starts at line 2.
        self.assertEqual(files[0].added[0].lineno, 2)
        self.assertEqual(files[0].added[1].lineno, 3)

    def test_context_lines_advance_line_numbers(self):
        files = parse_unified_diff(SAMPLE_DIFF)
        added = {line.text: line.lineno for line in files[0].added}
        self.assertEqual(added["    pass"], 7)


class TestChecks(unittest.TestCase):
    def test_hardcoded_secret_is_error(self):
        findings = review_files(parse_unified_diff(SAMPLE_DIFF))
        secret = [f for f in findings if f.rule == "SEC001"]
        self.assertEqual(len(secret), 1)
        self.assertEqual(secret[0].severity, "error")
        self.assertEqual(secret[0].line, 2)

    def test_eval_and_bare_except_flagged(self):
        findings = review_files(parse_unified_diff(SAMPLE_DIFF))
        rules = {f.rule for f in findings}
        self.assertIn("SEC002", rules)  # eval()
        self.assertIn("BUG001", rules)  # bare except:

    def test_missing_tests_flagged_when_no_test_file(self):
        findings = review_files(parse_unified_diff(MISSING_TESTS_DIFF))
        self.assertTrue(any(f.rule == "TST001" for f in findings))

    def test_no_findings_on_clean_diff(self):
        clean = """diff --git a/util.py b/util.py
--- a/util.py
+++ b/util.py
@@ -1,1 +1,2 @@
 def add(a, b):
+    return a + b
"""
        # util.py changed with no test file -> TST001 is expected; the
        # code itself must not produce any other finding.
        findings = review_files(parse_unified_diff(clean))
        self.assertEqual({f.rule for f in findings}, {"TST001"})

    def test_mutable_default_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def collect(items=[]):
+    items.append(1)
+    return items
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertTrue(any(f.rule == "BUG005" for f in findings))

    def test_long_function_flagged(self):
        body = "\n".join(f"+    step_{i}()" for i in range(55))
        diff = f"""diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,57 @@
+def big():
{body}
+    return None
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertTrue(any(f.rule == "CPL001" for f in findings))

    def test_markdown_files_are_skipped(self):
        diff = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,1 +1,2 @@
 # Title
+eval(user_input)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertEqual(findings, [])


    def test_too_many_returns_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,14 @@
+def pick(n):
+    if n == 1:
+        return "a"
+    if n == 2:
+        return "b"
+    if n == 3:
+        return "c"
+    if n == 4:
+        return "d"
+    if n == 5:
+        return "e"
+    if n == 6:
+        return "f"
+    return "z"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CPL004"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")

    def test_returns_inside_nested_function_not_counted(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,10 @@
+def outer(n):
+    def inner(x):
+        if x:
+            return 1
+        return 2
+    if n:
+        return inner(n)
+    return 0
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "CPL004" for f in findings))

    def test_boolean_flag_param_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def connect(host, verbose=True, retries=3):
+    return host
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CPL005"]
        self.assertEqual(len(flagged), 1)  # verbose only; retries=3 is not a bool
        self.assertEqual(flagged[0].severity, "info")

    def test_nested_and_long_comprehensions_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def grid(rows):
+    return [[x * y for y in row] for row in rows]
+def flat(matrix):
+    return [v for row in matrix for cell in row for v in cell]
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CPL006"]
        self.assertEqual(len(flagged), 2)  # nested once (outer only) + 3 generators
        self.assertTrue(all(f.severity == "warning" for f in flagged))

    def test_lambda_assignment_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,1 @@
+double = lambda n: n * 2
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CPL007"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")

    def test_clean_function_has_no_new_complexity_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def total(values):
+    return sum(v for v in values)
+square = None
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(rules & {"CPL004", "CPL005", "CPL006", "CPL007"})


class TestImportRules(unittest.TestCase):
    def test_wildcard_import_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+from helpers import *
+result = run()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IMP001"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")

    def test_unused_import_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+import os
+value = 42
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IMP002"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")

    def test_used_import_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+import os
+path = os.path.join("a", "b")
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "IMP002" for f in findings))

    def test_aliased_unused_import_flagged_on_alias(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+import numpy as np
+import json
+data = json.dumps({})
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IMP002"]
        self.assertEqual(len(flagged), 1)
        self.assertIn("np", flagged[0].message)

    def test_import_inside_function_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def load(path):
+    import json
+    return json.load(open(path))
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IMP003"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        # The import is used, so IMP002 must not fire for it.
        self.assertFalse(any(f.rule == "IMP002" for f in findings))

    def test_reexported_name_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+from helpers import run
+__all__ = ["run"]
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "IMP002" for f in findings))


class TestNamingRules(unittest.TestCase):
    def test_function_name_not_snake_case_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def GetUserData(user_id):
+    return user_id
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "NAM001"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertIn("get_user_data", flagged[0].suggestion)

    def test_snake_case_and_dunder_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def get_user_data(user_id):
+    return user_id
+class Cache:
+    def __init__(self):
+        pass
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "NAM001" for f in findings))

    def test_class_name_not_pascal_case_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+class user_record:
+    pass
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "NAM002"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertIn("UserRecord", flagged[0].suggestion)

    def test_pascal_case_class_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+class UserRecord:
+    pass
+class HTTPServer:
+    pass
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "NAM002" for f in findings))

    def test_module_constant_wrong_case_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+MaxRetries = 3
+TIMEOUT = 30
+max_retries = 3
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "NAM003"]
        self.assertEqual(len(flagged), 1)  # MaxRetries only
        self.assertEqual(flagged[0].severity, "info")
        self.assertIn("MAX_RETRIES", flagged[0].suggestion)

    def test_builtin_shadow_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def process(list, type):
+    return len(list)
+list = [1, 2]
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "NAM004"]
        # Two shadowed parameters + one shadowed assignment.
        self.assertEqual(len(flagged), 3)
        self.assertTrue(all(f.severity == "warning" for f in flagged))

    def test_method_shadowing_builtin_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+class Cache:
+    def id(self):
+        return 1
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "NAM004" for f in findings))

    def test_clean_names_no_naming_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+MAX_RETRIES = 3
+timeout = 30
+def fetch_user(user_id):
+    return users.get(user_id)
+class UserRecord:
+    pass
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(rules & {"NAM001", "NAM002", "NAM003", "NAM004"})


class TestStyleRules(unittest.TestCase):
    def test_trailing_whitespace_flagged(self):
        diff = (
            "diff --git a/x.py b/x.py\n"
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "@@ -1,0 +1,2 @@\n"
            "+value = 1   \n"
            "+clean = 2\n"
        )
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STY003"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_clean_lines_have_no_trailing_whitespace_finding(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+value = 1
+clean = 2
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "STY003" for f in findings))

    def test_semicolon_statements_flagged_once(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+name = "a"; count = 2
+total = 3
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STY004"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_comparison_to_singleton_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def check(flag):
+    if flag == None:
+        return True
+    if flag == False:
+        return False
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STY005"]
        self.assertEqual(len(flagged), 2)
        self.assertTrue(all(f.severity == "warning" for f in flagged))
        self.assertIn("None", flagged[0].message)

    def test_identity_comparison_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def check(flag):
+    if flag is None:
+        return True
+    return flag is not False
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "STY005" for f in findings))

    def test_tab_indentation_flagged(self):
        diff = (
            "diff --git a/x.py b/x.py\n"
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "@@ -1,0 +1,2 @@\n"
            "+def tabbed():\n"
            "+\treturn 1\n"
        )
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STY006"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 2)

    def test_clean_style_has_no_new_style_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def check(flag):
+    if flag is None:
+        return True
+    return False
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(rules & {"STY003", "STY004", "STY005", "STY006"})


class TestErrorRules(unittest.TestCase):
    def test_silent_except_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    load_config()
+except ValueError:
+    pass
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ERR001"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_except_with_logging_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    load_config()
+except ValueError as e:
+    logger.warning("config failed: %s", e)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "ERR001" for f in findings))

    def test_raise_without_from_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    load_config()
+except ValueError as e:
+    raise RuntimeError("bad config")
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ERR002"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 4)

    def test_raise_with_from_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    load_config()
+except ValueError as e:
+    raise RuntimeError("bad config") from e
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "ERR002" for f in findings))

    def test_bare_reraise_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    load_config()
+except ValueError:
+    raise
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "ERR002" for f in findings))

    def test_raise_from_none_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    load_config()
+except ValueError as e:
+    raise RuntimeError("bad config") from None
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "ERR002" for f in findings))

    def test_base_exception_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    stop_server()
+except BaseException:
+    cleanup()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ERR003"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_base_exception_in_tuple_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    stop_server()
+except (ValueError, BaseException):
+    cleanup()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ERR003"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 3)

    def test_useless_try_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+try:
+    pass
+except ValueError:
+    handle_error()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ERR004"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_clean_error_handling_no_err_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+try:
+    load_config()
+except ValueError as e:
+    logger.warning("config failed: %s", e)
+    raise RuntimeError("bad config") from e
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(rules & {"ERR001", "ERR002", "ERR003", "ERR004"})


class TestSecurityRules(unittest.TestCase):
    def test_subprocess_string_command_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+import subprocess
+subprocess.run("ls -la")
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "SEC101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 2)

    def test_subprocess_fstring_command_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+import subprocess
+subprocess.run(f"ls {directory}")
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "SEC101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 2)

    def test_subprocess_list_command_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+import subprocess
+subprocess.run(["ls", "-la"])
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "SEC101" for f in findings))

    def test_os_popen_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+import os
+def read_file(name):
+    return os.popen("cat " + name).read()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "SEC101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 3)

    def test_random_token_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+import random
+import string
+token = random.choice(string.ascii_letters)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "SEC102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertIn("token", flagged[0].message)

    def test_random_ordinary_variable_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+import random
+roll = random.randint(1, 6)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "SEC102" for f in findings))

    def test_assert_outside_tests_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def check_user(user):
+    assert user is not None, "user required"
+    return user
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "SEC103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 2)

    def test_assert_in_test_file_not_flagged(self):
        diff = """diff --git a/tests/test_example.py b/tests/test_example.py
--- a/tests/test_example.py
+++ b/tests/test_example.py
@@ -1,0 +1,2 @@
+def test_something():
+    assert 1 + 1 == 2
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "SEC103" for f in findings))

    def test_mktemp_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+import tempfile
+path = tempfile.mktemp()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "SEC104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 2)

    def test_chmod_world_writable_flagged_only(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+import os
+os.chmod(path, 0o777)
+os.chmod(other, 0o600)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "SEC105"]
        self.assertEqual(len(flagged), 1)  # 0o777 only; 0o600 is fine
        self.assertEqual(flagged[0].severity, "warning")
        self.assertIn("0o777", flagged[0].message)
        self.assertEqual(flagged[0].line, 2)

    def test_clean_security_no_new_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+import os
+import secrets
+import subprocess
+import tempfile
+token = secrets.token_hex(16)
+subprocess.run(["ls", "-la"])
+handle = tempfile.NamedTemporaryFile()
+os.chmod(path, 0o600)
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"SEC101", "SEC102", "SEC103", "SEC104", "SEC105"}
        )


class TestBugRules(unittest.TestCase):
    def test_unreachable_after_return_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def check(user):
+    if not user:
+        return None
+    return user
+    log_audit(user)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "BUG101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 5)

    def test_unreachable_after_raise_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def load_or_fail(path):
+    if not path:
+        raise ValueError("path required")
+        fallback_load(path)
+    return open(path)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "BUG101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 4)

    def test_code_after_conditional_return_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def check(user):
+    if not user:
+        return None
+    return user
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "BUG101" for f in findings))

    def test_duplicate_dict_key_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,1 @@
+settings = {"theme": "dark", "retries": 3, "theme": "light"}
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "BUG102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertIn("'theme'", flagged[0].message)
        self.assertEqual(flagged[0].line, 1)

    def test_distinct_dict_keys_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,1 @@
+settings = {"theme": "dark", "retries": 3}
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "BUG102" for f in findings))

    def test_identity_with_literal_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+if code is 200:
+    return "ok"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "BUG103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_identity_with_none_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+if user is None:
+    return None
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "BUG103" for f in findings))

    def test_constant_if_condition_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+if True:
+    enable_feature()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "BUG104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_while_true_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+while True:
+    wait_for_event()
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "BUG104" for f in findings))

    def test_while_false_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+while False:
+    process_next()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "BUG104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 1)

    def test_self_comparison_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def same(a, b):
+    if a == a:
+        return True
+    return False
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "BUG105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 2)

    def test_clean_code_no_bug_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,7 @@
+def greet(name):
+    if name is None:
+        return "stranger"
+    if name == "admin":
+        return "boss"
+    settings = {"theme": "dark", "retries": 3}
+    return f"hello {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"BUG101", "BUG102", "BUG103", "BUG104", "BUG105"}
        )


class TestPerformanceRules(unittest.TestCase):
    def test_string_concat_in_for_loop_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def build_message(parts):
+    message = ""
+    for part in parts:
+        message += part
+    return message
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "PERF101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 4)

    def test_string_concat_in_while_loop_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,7 @@
+def build_message(parts):
+    message = ""
+    index = 0
+    while index < len(parts):
+        message += parts[index]
+        index += 1
+    return message
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "PERF101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 5)

    def test_int_augassign_in_loop_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def total(numbers):
+    count = 0
+    for n in numbers:
+        count += n
+    return count
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "PERF101" for f in findings))

    def test_string_concat_outside_loop_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def build_message(parts):
+    message = ""
+    message += parts[0]
+    return message
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "PERF101" for f in findings))

    def test_range_len_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def show_indexes(items):
+    total = 0
+    for i in range(len(items)):
+        total += items[i]
+    return total
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "PERF102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_plain_range_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def show_items(items):
+    for i in range(5):
+        use(items[i])
+    return items
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "PERF102" for f in findings))

    def test_membership_in_list_literal_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def is_allowed(name):
+    return name in ["alice", "bob", "carol"]
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "PERF103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 2)

    def test_not_in_list_literal_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def is_blocked(name):
+    return name not in ["spam", "eggs"]
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "PERF103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 2)

    def test_membership_in_tuple_or_variable_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+ALLOWED = ("alice", "bob")
+
+def is_allowed(name):
+    if name in ALLOWED:
+        return True
+    return name in ("carol", "dave")
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "PERF103" for f in findings))

    def test_append_only_loop_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def squares(numbers):
+    result = []
+    for n in numbers:
+        result.append(n * n)
+    return result
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "PERF104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 4)

    def test_append_to_parameter_list_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def collect(out, numbers):
+    for n in numbers:
+        out.append(n * n)
+    return out
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "PERF104" for f in findings))

    def test_append_plus_other_work_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+def squares_logged(numbers):
+    result = []
+    for n in numbers:
+        result.append(n * n)
+        log(n)
+    return result
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "PERF104" for f in findings))

    def test_keys_iteration_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def show_keys(config):
+    count = 0
+    for key in config.keys():
+        count += 1
+    return count
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "PERF105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_direct_dict_iteration_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def show_keys(config):
+    count = 0
+    for key in config:
+        count += 1
+    return count
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "PERF105" for f in findings))

    def test_clean_code_no_perf_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def greet(name):
+    if name not in {"alice", "bob"}:
+        return "stranger"
+    parts = [f"hello {name}"]
+    return "".join(parts)
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"PERF101", "PERF102", "PERF103", "PERF104", "PERF105"}
        )


class TestDocRules(unittest.TestCase):
    def test_public_function_without_docstring_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def fetch_user(user_id):
+    return {"id": user_id}
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DOC101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_private_function_without_docstring_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def _helper(value):
+    return value * 2
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DOC101" for f in findings))

    def test_dunder_method_without_docstring_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+class Worker:
+    \"\"\"Does work.\"\"\"
+
+    def __init__(self):
+        self.x = 1
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DOC101" for f in findings))

    def test_test_function_without_docstring_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def test_something():
+    assert True
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DOC101" for f in findings))

    def test_public_class_without_docstring_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+class UserRecord:
+    def __init__(self, name):
+        self.name = name
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DOC102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_documented_function_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name):
+    \"\"\"Say hello.\"\"\"
+    return f"Hello {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DOC101" for f in findings))

    def test_empty_docstring_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def empty_doc():
+    \"\"\"\"\"\"
+    return None
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DOC103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 2)

    def test_whitespace_docstring_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def blank_doc():
+    \"\"\"   \"\"\"
+    return None
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DOC103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 2)

    def test_docstring_without_full_stop_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name):
+    \"\"\"Say hello\"\"\"
+    return f"Hello {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DOC104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 2)

    def test_docstring_with_full_stop_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name):
+    \"\"\"Say hello.\"\"\"
+    return f"Hello {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DOC104" for f in findings))

    def test_todo_in_docstring_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def stale_note():
+    \"\"\"Fetch the record. TODO: handle the missing case.\"\"\"
+    return None
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DOC105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 2)

    def test_clean_code_no_doc_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,11 @@
+\"\"\"Helpers.\"\"\"
+
+def greet(name):
+    \"\"\"Say hello.\"\"\"
+    return f"Hello {name}"
+
+
+class Greeter:
+    \"\"\"Greets people politely.\"\"\"
+
+    def __init__(self, name):
+        self.name = name
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"DOC101", "DOC102", "DOC103", "DOC104", "DOC105"}
        )


class TestTypingRules(unittest.TestCase):
    def test_public_function_without_return_annotation_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def fetch_user(user_id: int):
+    return {"id": user_id}
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "TYP101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_annotated_function_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def fetch_user(user_id: int) -> dict:
+    \"\"\"Fetch a user by id.\"\"\"
+    return {"id": user_id}
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "TYP101" for f in findings))

    def test_private_function_without_return_annotation_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def _helper(value: int) -> int:
+    return value * 2
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "TYP101" for f in findings))

    def test_test_function_without_return_annotation_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,2 @@
+def test_something() -> None:
+    assert True
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "TYP101" for f in findings))

    def test_unannotated_parameter_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name, greeting: str = "Hello") -> str:
+    \"\"\"Greet someone by name.\"\"\"
+    return f"{greeting} {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "TYP102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)
        self.assertIn("name", flagged[0].message)

    def test_self_and_annotated_params_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+class Worker:
+    \"\"\"Does work.\"\"\"
+
+    def run(self, job: str) -> None:
+        \"\"\"Run a job.\"\"\"
+        self.job = job
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "TYP102" for f in findings))

    def test_any_return_annotation_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def load_config(path: str) -> Any:
+    \"\"\"Load the config file.\"\"\"
+    return {}
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "TYP103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_any_parameter_annotation_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def process(data: Any) -> None:
+    \"\"\"Process data.\"\"\"
+    return None
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "TYP103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 1)

    def test_concrete_annotation_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def process(data: dict) -> str:
+    \"\"\"Process data.\"\"\"
+    return str(data)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "TYP103" for f in findings))

    def test_typing_list_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+import typing
+
+
+def collect(items: typing.List[str]) -> list:
+    \"\"\"Collect items.\"\"\"
+    return list(items)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "TYP104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 4)

    def test_bare_list_imported_from_typing_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+from typing import List
+
+
+def collect(items: List[str]) -> list:
+    \"\"\"Collect items.\"\"\"
+    return list(items)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "TYP104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 4)

    def test_builtin_generic_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def collect(items: list[str]) -> list[str]:
+    \"\"\"Collect items.\"\"\"
+    return items
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "TYP104" for f in findings))

    def test_none_function_returning_value_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def save_record(record: dict) -> None:
+    \"\"\"Save a record.\"\"\"
+    return record
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "TYP105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_none_function_with_bare_return_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def close() -> None:
+    \"\"\"Close the store.\"\"\"
+    return
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "TYP105" for f in findings))

    def test_clean_code_no_typing_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,11 @@
+\"\"\"Helpers.\"\"\"
+
+def greet(name: str) -> str:
+    \"\"\"Say hello.\"\"\"
+    return f"Hello {name}"
+
+
+def collect(items: list[str]) -> dict[str, int]:
+    \"\"\"Count items.\"\"\"
+    counts: dict[str, int] = {}
+    for item in items:
+        counts[item] = counts.get(item, 0) + 1
+    return counts
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"TYP101", "TYP102", "TYP103", "TYP104", "TYP105"}
        )


class TestAsyncRules(unittest.TestCase):
    def test_time_sleep_in_async_def_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+import asyncio
+import time
+
+
+async def slow() -> None:
+    \"\"\"Slow.\"\"\"
+    await asyncio.sleep(0)
+    time.sleep(5)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ASC101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 8)

    def test_bare_sleep_imported_from_time_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+import asyncio
+from time import sleep
+
+
+async def slow() -> None:
+    \"\"\"Slow.\"\"\"
+    await asyncio.sleep(0)
+    sleep(5)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ASC101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 8)

    def test_time_sleep_in_sync_function_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+import time
+
+
+def slow() -> None:
+    \"\"\"Slow.\"\"\"
+    time.sleep(5)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "ASC101" for f in findings))

    def test_async_call_without_await_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,12 @@
+import asyncio
+
+
+async def fetch_user(user_id: int) -> dict:
+    \"\"\"Fetch a user by id.\"\"\"
+    await asyncio.sleep(0)
+    return {"id": user_id}
+
+
+async def caller() -> None:
+    \"\"\"Call fetch_user.\"\"\"
+    fetch_user(1)
+    await fetch_user(2)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ASC102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 12)

    def test_awaited_and_scheduled_calls_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,13 @@
+import asyncio
+
+
+async def fetch_user(user_id: int) -> dict:
+    \"\"\"Fetch a user by id.\"\"\"
+    await asyncio.sleep(0)
+    return {"id": user_id}
+
+
+async def caller() -> None:
+    \"\"\"Schedule fetch_user.\"\"\"
+    task = asyncio.create_task(fetch_user(1))
+    await fetch_user(2)
+    await task
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(rules & {"ASC102", "ASC105"})

    def test_async_def_without_await_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+async def not_really_async() -> int:
+    \"\"\"Return a constant.\"\"\"
+    return 42
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ASC103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_awaited_generator_and_stub_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,15 @@
+import asyncio
+
+
+async def worker() -> None:
+    \"\"\"Work.\"\"\"
+    await asyncio.sleep(0)
+
+
+async def stream():
+    \"\"\"Yield values.\"\"\"
+    yield 1
+
+
+async def placeholder() -> None:
+    \"\"\"Do nothing yet.\"\"\"
+    ...
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "ASC103" for f in findings))

    def test_run_until_complete_in_async_def_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,14 @@
+import asyncio
+
+
+async def fetch_user(user_id: int) -> dict:
+    \"\"\"Fetch a user by id.\"\"\"
+    await asyncio.sleep(0)
+    return {"id": user_id}
+
+
+async def nested_loop() -> None:
+    \"\"\"Run through a loop.\"\"\"
+    await asyncio.sleep(0)
+    loop = asyncio.get_event_loop()
+    loop.run_until_complete(fetch_user(1))
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ASC104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 14)
        # The inner fetch_user call is scheduled, not forgotten.
        self.assertFalse(any(f.rule == "ASC102" for f in findings))

    def test_bare_create_task_flagged_but_assigned_not(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,20 @@
+import asyncio
+
+
+async def fetch_user(user_id: int) -> dict:
+    \"\"\"Fetch a user by id.\"\"\"
+    await asyncio.sleep(0)
+    return {"id": user_id}
+
+
+async def fire_and_forget() -> None:
+    \"\"\"Start a task.\"\"\"
+    await asyncio.sleep(0)
+    asyncio.create_task(fetch_user(1))
+
+
+async def careful() -> None:
+    \"\"\"Keep the task.\"\"\"
+    await asyncio.sleep(0)
+    task = asyncio.create_task(fetch_user(2))
+    await task
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "ASC105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 13)

    def test_clean_async_code_no_async_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,13 @@
+import asyncio
+
+
+async def fetch_user(user_id: int) -> dict:
+    \"\"\"Fetch a user by id.\"\"\"
+    await asyncio.sleep(0)
+    return {"id": user_id}
+
+
+async def caller() -> None:
+    \"\"\"Call fetch_user properly.\"\"\"
+    user = await fetch_user(1)
+    task = asyncio.create_task(fetch_user(2))
+    await task
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"ASC101", "ASC102", "ASC103", "ASC104", "ASC105"}
        )


class TestIdiomRules(unittest.TestCase):
    def test_open_outside_with_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def read(path: str) -> str:
+    \"\"\"Read a file.\"\"\"
+    handle = open(path)
+    return handle.readline()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IDM101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_open_inside_with_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def read(path: str) -> str:
+    \"\"\"Read a file.\"\"\"
+    with open(path) as handle:
+        return handle.readline()
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "IDM101" for f in findings))

    def test_type_comparison_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+def is_text(value: object) -> bool:
+    \"\"\"Check the type.\"\"\"
+    return type(value) == str
+
+
+def is_number(value: object) -> bool:
+    \"\"\"Check the type.\"\"\"
+    return type(value) is int
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IDM102"]
        self.assertEqual(len(flagged), 2)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual([f.line for f in flagged], [3, 8])

    def test_isinstance_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def is_text(value: object) -> bool:
+    \"\"\"Check the type.\"\"\"
+    return isinstance(value, str)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "IDM102" for f in findings))

    def test_len_compared_with_zero_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,18 @@
+def is_empty(items: list[str]) -> bool:
+    \"\"\"Check emptiness.\"\"\"
+    return len(items) == 0
+
+
+def has_items(items: list[str]) -> bool:
+    \"\"\"Check fullness.\"\"\"
+    return len(items) != 0
+
+
+def any_left(items: list[str]) -> bool:
+    \"\"\"Check anything left.\"\"\"
+    return len(items) > 0
+
+
+def empty_reversed(items: list[str]) -> bool:
+    \"\"\"Check emptiness, reversed.\"\"\"
+    return 0 == len(items)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IDM103"]
        self.assertEqual(len(flagged), 4)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual([f.line for f in flagged], [3, 8, 13, 18])

    def test_truthiness_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+def is_empty(items: list[str]) -> bool:
+    \"\"\"Check emptiness.\"\"\"
+    return not items
+
+
+def has_items(items: list[str]) -> bool:
+    \"\"\"Check fullness.\"\"\"
+    return bool(items)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "IDM103" for f in findings))

    def test_percent_formatting_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name: str) -> str:
+    \"\"\"Greet someone.\"\"\"
+    return "Hello, %s!" % name
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IDM104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_fstring_and_format_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+def greet(name: str) -> str:
+    \"\"\"Greet someone.\"\"\"
+    return f"Hello, {name}!"
+
+
+def greet2(name: str) -> str:
+    \"\"\"Greet someone.\"\"\"
+    return "Hello, {}!".format(name)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "IDM104" for f in findings))

    def test_in_keys_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+def has_key(mapping: dict[str, int], key: str) -> bool:
+    \"\"\"Check a key.\"\"\"
+    return key in mapping.keys()
+
+
+def lacks_key(mapping: dict[str, int], key: str) -> bool:
+    \"\"\"Check a key is missing.\"\"\"
+    return key not in mapping.keys()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "IDM105"]
        self.assertEqual(len(flagged), 2)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual([f.line for f in flagged], [3, 8])

    def test_in_dict_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def has_key(mapping: dict[str, int], key: str) -> bool:
+    \"\"\"Check a key.\"\"\"
+    return key in mapping
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "IDM105" for f in findings))

    def test_clean_idiomatic_code_no_idiom_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,23 @@
+def read(path: str) -> str:
+    \"\"\"Read a file.\"\"\"
+    with open(path) as handle:
+        return handle.readline()
+
+
+def is_text(value: object) -> bool:
+    \"\"\"Check the type.\"\"\"
+    return isinstance(value, str)
+
+
+def is_empty(items: list[str]) -> bool:
+    \"\"\"Check emptiness.\"\"\"
+    return not items
+
+
+def has_key(mapping: dict[str, int], key: str) -> bool:
+    \"\"\"Check a key.\"\"\"
+    return key in mapping
+
+
+def greet(name: str) -> str:
+    \"\"\"Greet someone.\"\"\"
+    return f"Hello, {name}!"
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"IDM101", "IDM102", "IDM103", "IDM104", "IDM105"}
        )


class TestLoggingRules(unittest.TestCase):
    def test_percent_format_in_logging_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def report_user(name: str) -> None:
+    \"\"\"Report a login, formatting eagerly.\"\"\"
+    logging.info("User %s logged in" % name)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "LOG101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_logging_with_args_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def report_user(name: str) -> None:
+    \"\"\"Report a login the lazy way.\"\"\"
+    logging.info("User %s logged in", name)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "LOG101" for f in findings))

    def test_fstring_in_logging_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def report_count(count: int) -> None:
+    \"\"\"Report a count, formatting eagerly.\"\"\"
+    logger.info(f"Processed {count} items")
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "LOG102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_plain_string_in_logging_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def report_done() -> None:
+    \"\"\"Report completion.\"\"\"
+    logging.info("All done")
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(
            any(f.rule in ("LOG101", "LOG102", "LOG104") for f in findings)
        )

    def test_exception_outside_handler_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,1 @@
+logging.exception("Something failed")
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "LOG103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_exception_inside_handler_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+def handle_error() -> None:
+    \"\"\"Log an error inside a handler.\"\"\"
+    try:
+        risky()
+    except ValueError:
+        logging.exception("Something failed")
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "LOG103" for f in findings))

    def test_exception_in_nested_def_inside_handler_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,9 @@
+def handle_error() -> None:
+    \"\"\"Define a logger inside a handler.\"\"\"
+    try:
+        risky()
+    except ValueError:
+        def log_later() -> None:
+            \"\"\"Log later, outside the handler.\"\"\"
+            logging.exception("Something failed")
+        log_later()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "LOG103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].line, 8)

    def test_format_call_in_logging_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def report_status(status: str) -> None:
+    \"\"\"Report a status, formatting eagerly.\"\"\"
+    logging.info("Status: {}".format(status))
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "LOG104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_warn_deprecated_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def warn_user() -> None:
+    \"\"\"Warn the user, the deprecated way.\"\"\"
+    logging.warn("Heads up")
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "LOG105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_warning_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def warn_user() -> None:
+    \"\"\"Warn the user, the current way.\"\"\"
+    logging.warning("Heads up")
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "LOG105" for f in findings))

    def test_clean_logging_code_no_logging_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,11 @@
+def report_user(name: str) -> None:
+    \"\"\"Report a login the lazy way.\"\"\"
+    logger.info("User %s logged in", name)
+
+
+def handle_error() -> None:
+    \"\"\"Log an error inside a handler.\"\"\"
+    try:
+        risky()
+    except ValueError:
+        logger.exception("Something failed")
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"LOG101", "LOG102", "LOG103", "LOG104", "LOG105"}
        )


class TestClassRules(unittest.TestCase):
    def test_data_only_class_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+class Config:
+    \"\"\"Settings, held as plain attributes.\"\"\"
+
+    host: str = "localhost"
+    port: int = 8080
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CLS101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_class_with_method_not_flagged_cls101(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,7 @@
+class Config:
+    \"\"\"Settings with a method.\"\"\"
+
+    host: str = "localhost"
+
+    def describe(self) -> str:
+        \"\"\"Describe the settings.\"\"\"
+        return self.host
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "CLS101" for f in findings))

    def test_redundant_init_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+class Child(Base):
+    \"\"\"Child that adds nothing.\"\"\"
+
+    def __init__(self, name: str) -> None:
+        \"\"\"Pass everything through.\"\"\"
+        super().__init__(name)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CLS102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 4)

    def test_init_doing_real_work_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+class Child(Base):
+    \"\"\"Child that adds its own state.\"\"\"
+
+    def __init__(self, name: str) -> None:
+        \"\"\"Store the name, then pass it on.\"\"\"
+        self.name = name
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "CLS102" for f in findings))

    def test_init_passing_subset_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+class Child(Base):
+    \"\"\"Child that keeps one argument back.\"\"\"
+
+    def __init__(self, name: str, extra: str) -> None:
+        \"\"\"Pass only the name through.\"\"\"
+        super().__init__(name)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "CLS102" for f in findings))

    def test_method_not_using_self_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+class Helper:
+    \"\"\"Helper whose method ignores the instance.\"\"\"
+
+    def greet(self) -> str:
+        \"\"\"Return a greeting.\"\"\"
+        return "hello"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CLS103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 4)

    def test_method_using_self_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+class Helper:
+    \"\"\"Helper whose method uses the instance.\"\"\"
+
+    def greet(self) -> str:
+        \"\"\"Return a greeting for this helper.\"\"\"
+        return f"hello {self.name}"
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "CLS103" for f in findings))

    def test_method_with_zero_arg_super_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+class Child(Base):
+    \"\"\"Child that overrides describe.\"\"\"
+
+    def describe(self) -> str:
+        \"\"\"Describe via the parent.\"\"\"
+        return super().describe()
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "CLS103" for f in findings))

    def test_staticmethod_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+class Helper:
+    \"\"\"Helper with a static method.\"\"\"
+
+    @staticmethod
+    def greet() -> str:
+        \"\"\"Return a greeting.\"\"\"
+        return "hello"
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "CLS103" for f in findings))

    def test_eq_without_hash_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,9 @@
+class Point:
+    \"\"\"A point with equality but no hash.\"\"\"
+
+    def __init__(self, x: int) -> None:
+        \"\"\"Store the coordinate.\"\"\"
+        self.x = x
+
+    def __eq__(self, other: object) -> bool:
+        \"\"\"Compare coordinates.\"\"\"
+        return isinstance(other, Point) and self.x == other.x
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CLS104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_eq_and_hash_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,13 @@
+class Point:
+    \"\"\"A point with equality and hash.\"\"\"
+
+    def __init__(self, x: int) -> None:
+        \"\"\"Store the coordinate.\"\"\"
+        self.x = x
+
+    def __eq__(self, other: object) -> bool:
+        \"\"\"Compare coordinates.\"\"\"
+        return isinstance(other, Point) and self.x == other.x
+
+    def __hash__(self) -> int:
+        \"\"\"Hash the coordinate.\"\"\"
+        return hash(self.x)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "CLS104" for f in findings))

    def test_empty_class_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+class Placeholder:
+    \"\"\"A class left empty.\"\"\"
+
+    pass
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "CLS105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_clean_class_no_class_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,17 @@
+class Widget:
+    \"\"\"A well-behaved class.\"\"\"
+
+    def __init__(self, label: str) -> None:
+        \"\"\"Store the label.\"\"\"
+        self.label = label
+
+    def describe(self) -> str:
+        \"\"\"Describe the widget.\"\"\"
+        return f"Widget: {self.label}"
+
+    def __eq__(self, other: object) -> bool:
+        \"\"\"Compare labels.\"\"\"
+        return isinstance(other, Widget) and self.label == other.label
+
+    def __hash__(self) -> int:
+        \"\"\"Hash the label.\"\"\"
+        return hash(self.label)
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"CLS101", "CLS102", "CLS103", "CLS104", "CLS105"}
        )


class TestFunctionRules(unittest.TestCase):
    def test_inconsistent_return_fall_off_end_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+def find_user(users: list[str], name: str) -> str | None:
+    \"\"\"Find a user by name, or return nothing.\"\"\"
+    for user in users:
+        if user == name:
+            return user
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "FN101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_inconsistent_return_bare_return_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+def check(value: int) -> str | None:
+    \"\"\"Return a label, or nothing at all.\"\"\"
+    if value > 0:
+        return "positive"
+    return
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "FN101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_if_else_both_returning_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+def pick(flag: bool) -> int:
+    \"\"\"Pick a number.\"\"\"
+    if flag:
+        return 1
+    else:
+        return 2
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "FN101" for f in findings))

    def test_single_return_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def add(a: int, b: int) -> int:
+    \"\"\"Add two numbers.\"\"\"
+    return a + b
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "FN101" for f in findings))

    def test_unused_parameter_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name: str, title: str) -> str:
+    \"\"\"Greet a user by name.\"\"\"
+    return f"Hello, {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "FN102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 1)

    def test_all_parameters_used_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name: str, title: str) -> str:
+    \"\"\"Greet a user by name and title.\"\"\"
+    return f"Hello, {title} {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "FN102" for f in findings))

    def test_self_parameter_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(self) -> str:
+    \"\"\"Return a greeting.\"\"\"
+    return "hello"
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "FN102" for f in findings))

    def test_parameter_used_in_nested_function_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+def outer(label: str) -> str:
+    \"\"\"Return the label via a nested helper.\"\"\"
+    def inner() -> str:
+        \"\"\"Return the outer label.\"\"\"
+        return label
+    return inner()
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "FN102" for f in findings))
        self.assertFalse(any(f.rule == "FN104" for f in findings))

    def test_return_value_in_generator_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+def stream_items(items: list[int]) -> Iterator[int]:
+    \"\"\"Yield each item, then report how many there were.\"\"\"
+    for item in items:
+        yield item
+    return len(items)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "FN103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 5)

    def test_generator_bare_return_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+def stream_items(items: list[int]) -> Iterator[int]:
+    \"\"\"Yield each item, then stop.\"\"\"
+    for item in items:
+        yield item
+    return
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "FN103" for f in findings))

    def test_dead_nested_function_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,7 @@
+def process_order(total: float, discount: float) -> float:
+    \"\"\"Apply a discount to an order total.\"\"\"
+    def apply_tax(amount: float) -> float:
+        \"\"\"Add tax to an amount.\"\"\"
+        return amount * 1.2
+
+    return total - discount
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "FN104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_called_nested_function_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,7 @@
+def process_order(total: float, discount: float) -> float:
+    \"\"\"Apply a discount and tax to an order total.\"\"\"
+    def apply_tax(amount: float) -> float:
+        \"\"\"Add tax to an amount.\"\"\"
+        return amount * 1.2
+
+    return apply_tax(total - discount)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "FN104" for f in findings))

    def test_call_default_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def create_user(name: str, created_at: datetime = datetime.now()) -> str:
+    \"\"\"Create a user stamped with the creation time.\"\"\"
+    return f"{name} joined at {created_at}"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "FN105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 1)

    def test_literal_default_not_flagged_fn105(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name: str, title: str = "Ms") -> str:
+    \"\"\"Greet a user by name and title.\"\"\"
+    return f"Hello, {title} {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "FN105" for f in findings))

    def test_clean_function_no_function_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+def total(items: list[int], tax: float) -> float:
+    \"\"\"Total a list of prices with tax.\"\"\"
+    subtotal = sum(items)
+    if tax <= 0:
+        return float(subtotal)
+    return float(subtotal) * (1 + tax)
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"FN101", "FN102", "FN103", "FN104", "FN105"}
        )


class TestStringRules(unittest.TestCase):
    def test_fstring_without_placeholder_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def status_label() -> str:
+    \"\"\"Return the current status label.\"\"\"
+    return f"ready"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STR101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_fstring_with_placeholder_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name: str) -> str:
+    \"\"\"Greet a user by name.\"\"\"
+    return f"Hello, {name}"
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "STR101" for f in findings))

    def test_empty_fstring_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def blank() -> str:
+    \"\"\"Return an empty string.\"\"\"
+    return f""
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STR101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_discarded_strip_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def clean_name(name: str) -> str:
+    \"\"\"Clean a display name.\"\"\"
+    name.strip()
+    return name
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STR102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_discarded_replace_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def fix_text(text: str) -> str:
+    \"\"\"Fix a piece of text.\"\"\"
+    text.replace("old", "new")
+    return text
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STR102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_assigned_strip_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def clean_name(name: str) -> str:
+    \"\"\"Clean a display name.\"\"\"
+    return name.strip()
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "STR102" for f in findings))

    def test_str_of_literal_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greeting_text() -> str:
+    \"\"\"Return a greeting.\"\"\"
+    return str("hello")
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STR103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_str_of_variable_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def as_text(value: int) -> str:
+    \"\"\"Return a value as text.\"\"\"
+    return str(value)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "STR103" for f in findings))

    def test_literal_concatenation_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def welcome_message() -> str:
+    \"\"\"Return a welcome message.\"\"\"
+    return "Welcome, " + "friend"
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STR104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_literal_plus_variable_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def greet(name: str) -> str:
+    \"\"\"Greet a user by name.\"\"\"
+    return "Hello, " + name
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "STR104" for f in findings))

    def test_join_on_string_literal_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def joined_letters() -> str:
+    \"\"\"Join letters with commas.\"\"\"
+    return ",".join("abc")
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "STR105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_join_on_list_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def joined_parts(parts: list[str]) -> str:
+    \"\"\"Join parts with commas.\"\"\"
+    return ",".join(parts)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "STR105" for f in findings))

    def test_clean_string_code_no_string_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def greet(name: str) -> str:
+    \"\"\"Greet a user by name.\"\"\"
+    cleaned = name.strip()
+    return f"Hello, {cleaned}"
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"STR101", "STR102", "STR103", "STR104", "STR105"}
        )


class TestReturnRules(unittest.TestCase):
    def test_sort_result_assigned_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def sorted_items(items: list[int]) -> list[int]:
+    \"\"\"Return the items in sorted order.\"\"\"
+    result = items.sort()
+    return result
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "RET101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_reverse_result_returned_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def reversed_items(items: list[int]) -> list[int]:
+    \"\"\"Return the items in reverse order.\"\"\"
+    return items.reverse()
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "RET101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_sort_bare_statement_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def tidy(items: list[int]) -> list[int]:
+    \"\"\"Sort the items and return them.\"\"\"
+    items.sort()
+    return items
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "RET101" for f in findings))

    def test_append_result_assigned_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def with_extra(items: list[int], extra: int) -> list[int]:
+    \"\"\"Return the items with one extra value added.\"\"\"
+    result = items.append(extra)
+    return result
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "RET102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_extend_result_returned_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def combined(items: list[int], more: list[int]) -> list[int]:
+    \"\"\"Return the items combined with more values.\"\"\"
+    return items.extend(more)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "RET102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_append_bare_statement_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def with_extra(items: list[int], extra: int) -> list[int]:
+    \"\"\"Return the items with one extra value added.\"\"\"
+    items.append(extra)
+    return items
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "RET102" for f in findings))

    def test_update_result_assigned_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def merged(settings: dict[str, int], extra: dict[str, int]) -> dict[str, int]:
+    \"\"\"Return the settings merged with the extras.\"\"\"
+    result = settings.update(extra)
+    return result
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "RET103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_update_bare_statement_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def merged(settings: dict[str, int], extra: dict[str, int]) -> dict[str, int]:
+    \"\"\"Return the settings merged with the extras.\"\"\"
+    settings.update(extra)
+    return settings
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "RET103" for f in findings))

    def test_shuffle_result_assigned_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+import random
+
+
+def shuffled(items: list[int]) -> list[int]:
+    \"\"\"Return the items in a random order.\"\"\"
+    result = random.shuffle(items)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "RET104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 6)

    def test_shuffle_bare_statement_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,6 @@
+import random
+
+
+def shuffled(items: list[int]) -> list[int]:
+    \"\"\"Return the items in a random order.\"\"\"
+    random.shuffle(items)
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "RET104" for f in findings))

    def test_add_result_assigned_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def with_tag(tags: set[str], tag: str) -> set[str]:
+    \"\"\"Return the tags with one more tag added.\"\"\"
+    result = tags.add(tag)
+    return result
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "RET105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_discard_result_returned_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def without_tag(tags: set[str], tag: str) -> set[str]:
+    \"\"\"Return the tags without one tag.\"\"\"
+    return tags.discard(tag)
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "RET105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_clean_return_code_no_return_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def sorted_with_extra(items: list[int], extra: int) -> list[int]:
+    \"\"\"Return the sorted items with one extra value added.\"\"\"
+    items.append(extra)
+    items.sort()
+    return items
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"RET101", "RET102", "RET103", "RET104", "RET105"}
        )


class TestDictRules(unittest.TestCase):
    def test_conditional_lookup_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def setting(settings: dict[str, int], key: str) -> int:
+    \"\"\"Return the setting for the key, or zero.\"\"\"
+    return settings[key] if key in settings else 0
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DCT101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_conditional_lookup_mirrored_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def setting(settings: dict[str, int], key: str) -> int:
+    \"\"\"Return the setting for the key, or zero.\"\"\"
+    return 0 if key not in settings else settings[key]
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DCT101"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_conditional_other_value_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+def setting(settings: dict[str, int], key: str) -> int:
+    \"\"\"Return one when the key exists, or zero.\"\"\"
+    return 1 if key in settings else 0
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DCT101" for f in findings))

    def test_if_else_lookup_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,7 @@
+def setting(settings: dict[str, int], key: str) -> int:
+    \"\"\"Return the setting for the key, or zero.\"\"\"
+    if key in settings:
+        value = settings[key]
+    else:
+        value = 0
+    return value
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DCT102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_if_else_lookup_mirrored_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,7 @@
+def setting(settings: dict[str, int], key: str) -> int:
+    \"\"\"Return the setting for the key, or zero.\"\"\"
+    if key not in settings:
+        value = 0
+    else:
+        value = settings[key]
+    return value
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DCT102"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_if_else_different_targets_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+def setting(settings: dict[str, int], key: str) -> int:
+    \"\"\"Return the setting for the key, or zero.\"\"\"
+    value = 0
+    if key in settings:
+        value = settings[key]
+    else:
+        other = 0
+    return value
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DCT102" for f in findings))

    def test_insert_default_by_hand_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def ensure(counts: dict[str, int], key: str) -> int:
+    \"\"\"Return the count for the key, starting at zero.\"\"\"
+    if key not in counts:
+        counts[key] = 0
+    return counts[key]
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DCT103"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_assign_other_key_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def ensure(counts: dict[str, int], key: str) -> int:
+    \"\"\"Return the count for the key, starting at zero.\"\"\"
+    if key not in counts:
+        counts["total"] = 0
+    return counts[key]
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DCT103" for f in findings))

    def test_empty_dict_call_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def empty() -> dict[str, int]:
+    \"\"\"Return an empty settings dict.\"\"\"
+    settings = dict()
+    return settings
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DCT104"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "info")
        self.assertEqual(flagged[0].line, 3)

    def test_dict_call_with_arguments_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,5 @@
+def copied(settings: dict[str, int]) -> dict[str, int]:
+    \"\"\"Return a copy of the settings.\"\"\"
+    first = dict(settings)
+    second = dict(timeout=30)
+    return first
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DCT104" for f in findings))

    def test_self_update_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def bump(counts: dict[str, int], key: str) -> int:
+    \"\"\"Add one to the count for the key and return it.\"\"\"
+    counts[key] = counts[key] + 1
+    return counts[key]
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DCT105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_self_update_multiply_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def double(counts: dict[str, int], key: str) -> int:
+    \"\"\"Double the count for the key and return it.\"\"\"
+    counts[key] = counts[key] * 2
+    return counts[key]
"""
        findings = review_files(parse_unified_diff(diff))
        flagged = [f for f in findings if f.rule == "DCT105"]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0].severity, "warning")
        self.assertEqual(flagged[0].line, 3)

    def test_augmented_update_not_flagged(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,4 @@
+def bump(counts: dict[str, int], key: str) -> int:
+    \"\"\"Add one to the count for the key and return it.\"\"\"
+    counts[key] += 1
+    return counts[key]
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertFalse(any(f.rule == "DCT105" for f in findings))

    def test_clean_dict_code_no_dict_findings(self):
        diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,8 @@
+def setting(settings: dict[str, int], key: str) -> int:
+    \"\"\"Return the setting for the key, or zero.\"\"\"
+    return settings.get(key, 0)
+
+
+def ensure(counts: dict[str, int], key: str) -> int:
+    \"\"\"Return the count for the key, starting at zero.\"\"\"
+    return counts.setdefault(key, 0)
"""
        findings = review_files(parse_unified_diff(diff))
        rules = {f.rule for f in findings}
        self.assertFalse(
            rules & {"DCT101", "DCT102", "DCT103", "DCT104", "DCT105"}
        )


class TestIgnoreRules(unittest.TestCase):
    IGNORE_DIFF = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,0 +1,3 @@
+print("hello")
+eval(user_input)
+# TODO: handle this properly
"""

    def test_ignored_rule_is_dropped_but_others_kept(self):
        findings = review_files(
            parse_unified_diff(self.IGNORE_DIFF), {"STY002"}
        )
        rules = {f.rule for f in findings}
        self.assertNotIn("STY002", rules)
        self.assertIn("SEC002", rules)  # eval() still flagged
        self.assertIn("BUG003", rules)  # TODO still flagged

    def test_ignore_is_case_insensitive(self):
        findings = review_files(
            parse_unified_diff(self.IGNORE_DIFF), {"sec002", " sty002 "}
        )
        rules = {f.rule for f in findings}
        self.assertNotIn("SEC002", rules)
        self.assertNotIn("STY002", rules)
        self.assertIn("BUG003", rules)

    def test_pr_level_rule_can_be_ignored(self):
        findings = review_files(
            parse_unified_diff(MISSING_TESTS_DIFF), {"TST001"}
        )
        self.assertEqual(findings, [])

    def test_unknown_rule_id_is_ignored_harmlessly(self):
        findings = review_files(
            parse_unified_diff(self.IGNORE_DIFF), {"NOPE999"}
        )
        rules = {f.rule for f in findings}
        self.assertIn("SEC002", rules)
        self.assertIn("STY002", rules)

    def test_no_ignore_argument_behaves_as_before(self):
        findings = review_files(parse_unified_diff(SAMPLE_DIFF))
        self.assertTrue(any(f.rule == "SEC001" for f in findings))


class TestReport(unittest.TestCase):
    def test_verdict_clean(self):
        self.assertIn("No issues", verdict([]))

    def test_report_contains_marker_and_rules(self):
        findings = review_files(parse_unified_diff(SAMPLE_DIFF))
        body = render_report(findings, "taha080/ai-pr-reviewer-action", 7)
        self.assertIn("<!-- ai-pr-reviewer -->", body)
        self.assertIn("SEC001", body)
        self.assertIn("#7", body)


if __name__ == "__main__":
    unittest.main()
