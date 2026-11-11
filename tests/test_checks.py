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
