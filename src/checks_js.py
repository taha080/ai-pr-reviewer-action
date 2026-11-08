"""JavaScript / TypeScript review rules for PR diffs.

Line-based rules for ``.js`` / ``.jsx`` / ``.ts`` / ``.tsx`` files, following
the same shape as the Python rules in :mod:`src.checks`: each finding carries
a stable rule id (``JS001`` …), a severity and a fix suggestion.

Complexity rules (``JS011``–``JS013``) mirror the Python complexity rules
(``CPL001``–``CPL003``) but are implemented with a small brace-tracking
scanner instead of a parser, so they stay dependency-free. They are
best-effort: a function whose closing brace is not in the added lines (a
partial fragment) is skipped for length/nesting, and braces inside string
literals or comments are ignored. Braces that open an object literal do not
count towards nesting — only braces after ``)``, ``=>``, ``else``, ``do``,
``try`` or ``finally`` do.

The rules run on added lines only, so pre-existing code is never nagged
about. They are applied by :func:`src.checks.review_files`, which imports
this module lazily to avoid a circular import (this module needs
:class:`src.checks.Finding`).
"""

from __future__ import annotations

import re
from bisect import bisect_right
from dataclasses import dataclass

from .checks import Finding
from .diffparse import ChangedFile

JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

MAX_JS_FUNCTION_LINES = 50
MAX_JS_FUNCTION_ARGS = 5
MAX_JS_NESTING_DEPTH = 3


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
    """Run the JS/TS line rules and complexity rules over one file."""
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
    findings.extend(_check_js_complexity(changed))
    return findings


# ---------------------------------------------------------------------------
# JS/TS complexity rules (JS011–JS013): brace-tracking scanner
# ---------------------------------------------------------------------------

_CONTROL_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "with", "do", "return",
    "typeof", "new", "delete", "void", "in", "of", "instanceof",
    "await", "yield", "else", "try", "finally", "class", "extends",
}

# A function definition, in its three common shapes:
#   function name(params) { ... } / function (params) { ... }
#   const name = [async] [function name] (params) => { ... }
#   name(params) { ... }            (method shorthand / class method)
_FUNCTION_RE = re.compile(
    r"(?:function\s*\*?\s*(?P<fname>[A-Za-z_$][\w$]*)?\s*"
    r"|(?:const|let|var)\s+(?P<vname>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?"
    r"(?:function\s*\*?\s*(?P<afname>[A-Za-z_$][\w$]*)?\s*)?"
    r"|(?P<mname>[A-Za-z_$][\w$]*)\s*)"
    r"\("
)

# Single-parameter arrow function without parens: const f = x => { ... }
_ARROW_SINGLE_PARAM_RE = re.compile(
    r"(?:const|let|var)\s+(?P<aname>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?"
    r"(?P<aparam>[A-Za-z_$][\w$]*)\s*=>\s*\{"
)

# Words before a "{" that mean it opens a block, not an object literal.
_BLOCK_OPEN_WORDS = {"else", "do", "try", "finally"}


def _blank_strings_and_comments(text: str) -> str:
    """Replace string literals and comments with spaces (newlines kept).

    The result keeps the same length and line breaks as ``text``, so an
    index in the cleaned text maps to the same line in the original.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"`":
            j = i + 1
            while j < n and text[j] != ch:
                if text[j] == "\\":
                    j += 1
                j += 1
            end = j + 1 if j < n else j
            out.append(re.sub(r"[^\n]", " ", text[i:end]))
            i = end
        elif ch == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            end = n if j == -1 else j
            out.append(" " * (end - i))
            i = end
        elif ch == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            end = n if j == -1 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:end]))
            i = end
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _matching_paren(text: str, open_idx: int) -> int:
    """Index of the ``)`` matching the ``(`` at ``open_idx``, or -1."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _count_params(params: str) -> int:
    """Count top-level parameters, so destructuring/defaults count as one."""
    params = params.strip()
    if not params:
        return 0
    depth = 0
    count = 1
    for ch in params:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            count += 1
    return count


def _is_block_brace(text: str, idx: int) -> bool:
    """True if the ``{`` at ``idx`` opens a block rather than an object."""
    j = idx - 1
    while j >= 0 and text[j] in " \t\r\n":
        j -= 1
    if j < 0:
        return False
    if text[j] in ")>":
        return True
    if text[j].isalpha() or text[j] in "_$":
        k = j
        while k >= 0 and (text[k].isalnum() or text[k] in "_$"):
            k -= 1
        return text[k + 1:j + 1] in _BLOCK_OPEN_WORDS
    return False


def _scan_body(text: str, brace_idx: int) -> tuple[int, int] | None:
    """Scan a ``{ ... }`` body starting at ``brace_idx``.

    Returns ``(end_index, max_nesting)`` where ``max_nesting`` counts only
    block braces nested inside the body, or ``None`` if the body is not
    closed within ``text`` (a partial fragment).
    """
    depth = 1
    stack = [True]  # the function body itself opens a block
    max_nesting = 1
    k = brace_idx + 1
    while k < len(text):
        if text[k] == "{":
            depth += 1
            stack.append(_is_block_brace(text, k))
            if stack[-1]:
                max_nesting = max(max_nesting, sum(stack))
        elif text[k] == "}":
            depth -= 1
            stack.pop()
            if depth == 0:
                return k, max_nesting
        k += 1
    return None


def _check_js_complexity(changed: ChangedFile) -> list[Finding]:
    """Flag long functions, too many parameters and deep nesting in JS/TS.

    Runs on the added lines only. A function whose body is not closed
    inside the added lines is skipped for length/nesting (it is a fragment),
    but its parameter count is still checked.
    """
    if not changed.path.endswith(JS_EXTENSIONS):
        return []
    lines = [line.text for line in changed.added]
    if not lines:
        return []
    text = "\n".join(lines)
    clean = _blank_strings_and_comments(text)
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    real_lineno = [line.lineno for line in changed.added]

    def _line_of(idx: int) -> int:
        pos = bisect_right(starts, idx) - 1
        return real_lineno[pos] if 0 <= pos < len(real_lineno) else 0

    def _check_params(
        name: str | None, arg_count: int, start_idx: int
    ) -> list[Finding]:
        """Flag a function that takes too many parameters (JS012)."""
        if arg_count <= MAX_JS_FUNCTION_ARGS:
            return []
        label = f"'{name}'" if name else "anonymous function"
        return [
            Finding(changed.path, _line_of(start_idx), "info", "JS012",
                    f"Function {label} takes {arg_count} arguments "
                    f"(over {MAX_JS_FUNCTION_ARGS}).",
                    "Group related arguments into an options object.")
        ]

    def _check_body(
        name: str | None, start_idx: int, brace_idx: int
    ) -> list[Finding]:
        """Flag a long function (JS011) or one nested too deep (JS013)."""
        label = f"'{name}'" if name else "anonymous function"
        start_line = _line_of(start_idx)
        scanned = _scan_body(clean, brace_idx)
        if scanned is None:
            return []  # body not closed in the added lines: can't measure
        end_idx, max_nesting = scanned
        out: list[Finding] = []
        span = _line_of(end_idx) - start_line + 1
        if span > MAX_JS_FUNCTION_LINES:
            out.append(
                Finding(changed.path, start_line, "warning", "JS011",
                        f"Function {label} is {span} lines long "
                        f"(over {MAX_JS_FUNCTION_LINES}).",
                        "Split it into smaller helpers with one job each.")
            )
        nesting = max_nesting - 1  # levels nested inside the function body
        if nesting > MAX_JS_NESTING_DEPTH:
            out.append(
                Finding(changed.path, start_line, "warning", "JS013",
                        f"Function {label} nests {nesting} levels deep "
                        f"(over {MAX_JS_NESTING_DEPTH}).",
                        "Extract the inner branches into guard clauses or helpers.")
            )
        return out

    findings: list[Finding] = []
    seen_parens: set[int] = set()

    def _body_brace_after(close_idx: int) -> int | None:
        """Index of the ``{`` opening a function body after ``close_idx``."""
        j = close_idx + 1
        while j < len(clean) and clean[j] in " \t\r\n":
            j += 1
        if clean[j:j + 2] == "=>":
            j += 2
            while j < len(clean) and clean[j] in " \t\r\n":
                j += 1
        if j < len(clean) and clean[j] == "{":
            return j
        return None

    for match in _FUNCTION_RE.finditer(clean):
        name = (
            match.group("fname")
            or match.group("afname")
            or match.group("vname")
            or match.group("mname")
        )
        if match.group("mname") and match.group("mname") in _CONTROL_KEYWORDS:
            continue
        open_idx = match.end() - 1  # the "(" matched by the pattern
        if open_idx in seen_parens:
            continue
        seen_parens.add(open_idx)
        close_idx = _matching_paren(clean, open_idx)
        if close_idx == -1:
            continue
        findings.extend(
            _check_params(
                name, _count_params(clean[open_idx + 1:close_idx]), match.start()
            )
        )
        brace_idx = _body_brace_after(close_idx)
        if brace_idx is None:
            continue  # expression-bodied arrow or a call, not a function
        findings.extend(_check_body(name, match.start(), brace_idx))

    for match in _ARROW_SINGLE_PARAM_RE.finditer(clean):
        brace_idx = match.end() - 1  # the "{" matched by the pattern
        findings.extend(
            _check_body(match.group("aname"), match.start(), brace_idx)
        )

    return findings
