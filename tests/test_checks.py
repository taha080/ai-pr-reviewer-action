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
