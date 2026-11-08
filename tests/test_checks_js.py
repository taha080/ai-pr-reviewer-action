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

    def test_debugger_with_trailing_comment_flagged(self):
        # Regression: the dogfood PR showed JS002 missed "debugger; // note"
        # because the old rule only matched a bare debugger line.
        diff = """diff --git a/dbg.js b/dbg.js
--- a/dbg.js
+++ b/dbg.js
@@ -1,1 +1,2 @@
 function run() {
+  debugger; // TODO: remove before merge
"""
        findings = review_files(parse_unified_diff(diff))
        self.assertTrue(any(f.rule == "JS002" for f in findings))

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


def _js_diff(path, body_lines):
    """Build a diff where the whole file body is added lines."""
    added = "\n".join(f"+{line}" for line in body_lines)
    return (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(body_lines)} @@\n"
        f"{added}\n"
    )


class TestJsComplexity(unittest.TestCase):
    def test_long_function_flagged_js011(self):
        body = ["function huge() {"] + [f"  const v{i} = {i};" for i in range(52)] + ["}"]
        findings = review_files(parse_unified_diff(_js_diff("big.js", body)))
        js011 = [f for f in findings if f.rule == "JS011"]
        self.assertEqual(len(js011), 1)
        self.assertIn("54 lines", js011[0].message)
        self.assertEqual(js011[0].line, 1)

    def test_short_function_is_clean(self):
        body = ["function small() {"] + [f"  const v{i} = {i};" for i in range(8)] + ["}"]
        findings = review_files(parse_unified_diff(_js_diff("small.js", body)))
        self.assertNotIn("JS011", {f.rule for f in findings})

    def test_arrow_function_length_flagged(self):
        body = ["const run = () => {"] + [f"  const v{i} = {i};" for i in range(52)] + ["};"]
        findings = review_files(parse_unified_diff(_js_diff("arrow.js", body)))
        self.assertIn("JS011", {f.rule for f in findings})

    def test_too_many_params_flagged_js012(self):
        body = ["function many(a, b, c, d, e, f) {", "  return a;", "}"]
        findings = review_files(parse_unified_diff(_js_diff("many.js", body)))
        js012 = [f for f in findings if f.rule == "JS012"]
        self.assertEqual(len(js012), 1)
        self.assertIn("6 arguments", js012[0].message)

    def test_five_params_and_destructuring_are_clean(self):
        body = [
            "function ok(a, b, c, d, e) {",
            "  return a;",
            "}",
            "function alsoOk({x, y}, opts = {a: 1, b: 2}) {",
            "  return opts;",
            "}",
        ]
        findings = review_files(parse_unified_diff(_js_diff("ok.js", body)))
        self.assertNotIn("JS012", {f.rule for f in findings})

    def test_arrow_with_many_params_flagged(self):
        body = ["const f = (a, b, c, d, e, f) => a;", ""]
        findings = review_files(parse_unified_diff(_js_diff("arr.js", body)))
        self.assertIn("JS012", {f.rule for f in findings})

    def test_deep_nesting_flagged_js013(self):
        body = [
            "function deep(x) {",
            "  if (x) {",
            "    if (x) {",
            "      if (x) {",
            "        if (x) {",
            "          return 1;",
            "        }",
            "      }",
            "    }",
            "  }",
            "  return 0;",
            "}",
        ]
        findings = review_files(parse_unified_diff(_js_diff("deep.js", body)))
        js013 = [f for f in findings if f.rule == "JS013"]
        self.assertEqual(len(js013), 1)
        self.assertIn("4 levels", js013[0].message)

    def test_three_levels_of_nesting_are_clean(self):
        body = [
            "function shallow(x) {",
            "  if (x) {",
            "    if (x) {",
            "      if (x) {",
            "        return 1;",
            "      }",
            "    }",
            "  }",
            "  return 0;",
            "}",
        ]
        findings = review_files(parse_unified_diff(_js_diff("shallow.js", body)))
        self.assertNotIn("JS013", {f.rule for f in findings})

    def test_nested_object_literal_is_not_nesting(self):
        body = [
            "function config() {",
            "  const opts = { a: 1, b: { c: 2, d: { e: 3 } } };",
            "  return opts;",
            "}",
        ]
        findings = review_files(parse_unified_diff(_js_diff("cfg.js", body)))
        self.assertNotIn("JS013", {f.rule for f in findings})

    def test_partial_fragment_skips_length_but_checks_params(self):
        # Closing brace is not in the added lines: length/nesting unknown,
        # but the 6-parameter signature is still flagged.
        body = [
            "function partial(a, b, c, d, e, f) {",
            "  const x = 1;",
            "  const y = 2;",
        ]
        findings = review_files(parse_unified_diff(_js_diff("part.js", body)))
        rules = {f.rule for f in findings}
        self.assertIn("JS012", rules)
        self.assertNotIn("JS011", rules)
        self.assertNotIn("JS013", rules)

    def test_method_shorthand_measured(self):
        body = ["class S {", "  handle() {"] + [f"    const v{i} = {i};" for i in range(52)] + ["  }", "}"]
        findings = review_files(parse_unified_diff(_js_diff("cls.js", body)))
        self.assertIn("JS011", {f.rule for f in findings})
