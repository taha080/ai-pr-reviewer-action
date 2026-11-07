"""JavaScript / TypeScript review rules for PR diffs.

Line-based rules for ``.js`` / ``.jsx`` / ``.ts`` / ``.tsx`` files, following
the same shape as the Python rules in :mod:`src.checks`: each finding carries
a stable rule id (``JS001`` …), a severity and a fix suggestion.

The rules run on added lines only, so pre-existing code is never nagged
about. They are applied by :func:`src.checks.review_files`, which imports
this module lazily to avoid a circular import (this module needs
:class:`src.checks.Finding`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .checks import Finding
from .diffparse import ChangedFile

JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


@dataclass
class _LineRule:
    pattern: re.Pattern[str]
    severity: str
    rule: str
    message: str
    suggestion: str


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


JS_RULES: list[_LineRule] = [
    _LineRule(
        _r(r"\bconsole\.(log|debug|info)\s*\("),
        "warning", "JS001",
        "console.log()/debug()/info() left in added code.",
        "Remove it before merging, or use a proper logger.",
    ),
    _LineRule(
        _r(r"^\s*debugger\b"),
        "warning", "JS002",
        "debugger statement left in added code.",
        "Remove it — it pauses execution for anyone with devtools open.",
    ),
    _LineRule(
        _r(r"(^|[^\w$.])var\s+\w+\s*="),
        "info", "JS003",
        "var declaration — use let or const instead.",
        "var is function-scoped and hoisted; let/const make the scope obvious.",
    ),
    _LineRule(
        _r(r"(?<![=!<>])==(?!=)|(?<![=!<>])!=(?!=)"),
        "warning", "JS004",
        "Loose equality (== / !=) — use strict equality (=== / !==).",
        "Loose equality coerces types and hides bugs; strict equality is explicit.",
    ),
    _LineRule(
        _r(r"\bdocument\.write\s*\("),
        "warning", "JS005",
        "document.write() blocks parsing and is an XSS vector.",
        "Build DOM nodes or use textContent/innerHTML on a specific element instead.",
    ),
    _LineRule(
        _r(r"\.innerHTML\s*="),
        "warning", "JS006",
        "Assignment to innerHTML can inject unescaped markup (XSS).",
        "Use textContent for plain text, or sanitise the HTML first.",
    ),
    _LineRule(
        _r(r"\bparseInt\s*\(\s*[^,)]+\s*\)"),
        "info", "JS007",
        "parseInt() called without a radix.",
        "Pass the radix explicitly, e.g. parseInt(value, 10).",
    ),
    _LineRule(
        _r(r"\b(alert|confirm|prompt)\s*\("),
        "info", "JS008",
        "Blocking browser dialog (alert/confirm/prompt) in added code.",
        "Use a non-blocking UI element instead; dialogs freeze the page.",
    ),
    _LineRule(
        _r(r"\bnew\s+Function\s*\("),
        "error", "JS009",
        "new Function() executes a string as code, like eval().",
        "Define the function directly instead of building it from a string.",
    ),
    _LineRule(
        _r(r":\s*any\b"),
        "info", "JS010",
        "Explicit `any` type defeats TypeScript's type checking.",
        "Use a precise type, unknown, or a generic instead.",
    ),
]


def check_js(changed: ChangedFile) -> list[Finding]:
    """Run the JS/TS line rules over the added lines of one file."""
    if not changed.path.endswith(JS_EXTENSIONS):
        return []
    findings: list[Finding] = []
    for added in changed.added:
        for rule in JS_RULES:
            if rule.pattern.search(added.text):
                findings.append(
                    Finding(
                        path=changed.path,
                        line=added.lineno,
                        severity=rule.severity,
                        rule=rule.rule,
                        message=rule.message,
                        suggestion=rule.suggestion,
                    )
                )
    return findings
