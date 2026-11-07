"""Tests for the JavaScript / TypeScript rule set (src/checks_js.py).

Run with:  python3 -m unittest discover -s tests -v
Only the standard library is used.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.checks import review_files  # noqa: E402
from src.diffparse import parse_unified_diff  # noqa: E402


JS_DIFF = """diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -1,3 +1,10 @@
 function greet(name) {
+  console.log("hi", name);
+  debugger;
+  var count = 0;
+  if (name == "admin") {
+    document.write("welcome");
+    el.innerHTML = name;
+  }
+  return parseInt(count);
 }
"""

TS_DIFF = """diff --git a/util.ts b/util.ts
--- a/util.ts
+++ b/util.ts
@@ -1,1 +1,3 @@
 export function run() {
+  const handler = new Function("return 1");
+  const value: any = getData();
 }
"""


class TestJsRules(unittest.TestCase):
    def test_console_log_and_debugger_flagged(self):
        findings = review_files(parse_unified_diff(JS_DIFF))
        rules = {f.rule for f in findings}
        self.assertIn("JS001", rules)  # console.log
        self.assertIn("JS002", rules)  # debugger

    def test_var_and_loose_equality_flagged(self):
        findings = review_files(parse_unified_diff(JS_DIFF))
        rules = {f.rule for f in findings}
        self.assertIn("JS003", rules)  # var
        self.assertIn("JS004", rules)  # ==

    def test_document_write_innerhtml_parseint_flagged(self):
        findings = review_files(parse_unified_diff(JS_DIFF))
        rules = {f.rule for f in findings}
        self.assertIn("JS005", rules)  # document.write
        self.assertIn("JS006", rules)  # innerHTML =
        self.assertIn("JS007", rules)  # parseInt without radix

    def test_new_function_and_any_flagged_in_ts(self):
        findings = review_files(parse_unified_diff(TS_DIFF))
        rules = {f.rule for f in findings}
        self.assertIn("JS009", rules)  # new Function()
        self.assertIn("JS010", rules)  # : any

    def test_strict_equality_and_radix_are_clean(self):
        clean = """diff --git a/clean.js b/clean.js
--- a/clean.js
+++ b/clean.js
@@ -1,1 +1,4 @@
 function check(a, b) {
+  const ok = a === b && a !== null;
+  const n = parseInt("42", 10);
+  return ok ? n : 0;
 }
"""
        findings = review_files(parse_unified_diff(clean))
        rules = {f.rule for f in findings}
        self.assertNotIn("JS004", rules)
        self.assertNotIn("JS007", rules)

    def test_js_rules_do_not_fire_on_python(self):
        py = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,1 +1,2 @@
 def check(a, b):
+    return a == b
"""
        findings = review_files(parse_unified_diff(py))
        rules = {f.rule for f in findings}
        self.assertNotIn("JS004", rules)


if __name__ == "__main__":
    unittest.main()
