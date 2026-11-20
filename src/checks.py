"""Static review rules for PR diffs.

Rules are grouped by category and each finding carries a stable rule id,
a severity and a short fix suggestion, so the report can link a finding
back to the exact rule that produced it.

The checks run on added lines only — reviewers should not be nagged about
pre-existing code they did not touch. Python AST checks run on the added
lines of ``.py`` files; they are best-effort (a fragment that does not
parse is simply skipped).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .diffparse import ChangedFile

MAX_LINE_LENGTH = 120
MAX_FUNCTION_LINES = 50
MAX_FUNCTION_ARGS = 5
MAX_NESTING_DEPTH = 3
MAX_FUNCTION_RETURNS = 5
MAX_COMPREHENSION_GENERATORS = 2

# Builtin names worth never rebinding: rebinding one hides it for the
# whole scope, so `list = [...]` breaks every later `list(...)` call.
_BUILTIN_NAMES = frozenset({
    # Types
    "bool", "bytearray", "bytes", "complex", "dict", "float", "frozenset",
    "int", "list", "object", "set", "slice", "str", "tuple", "type",
    # Functions
    "abs", "all", "any", "ascii", "bin", "breakpoint", "callable", "chr",
    "compile", "delattr", "dir", "divmod", "enumerate", "eval", "exec",
    "filter", "format", "getattr", "globals", "hasattr", "hash", "help",
    "hex", "id", "input", "isinstance", "issubclass", "iter", "len",
    "locals", "map", "max", "memoryview", "min", "next", "oct", "open",
    "ord", "pow", "print", "range", "repr", "reversed", "round", "setattr",
    "sorted", "sum", "super", "vars", "zip",
    # Common exceptions
    "ArithmeticError", "AssertionError", "AttributeError", "Exception",
    "FileNotFoundError", "ImportError", "IndexError", "KeyError",
    "LookupError", "NameError", "NotImplementedError", "OSError",
    "RuntimeError", "StopIteration", "TypeError", "ValueError",
    "ZeroDivisionError",
})

_SNAKE_CASE = re.compile(r"^[a-z_][a-z0-9_]*$")
_PASCAL_CASE = re.compile(r"^[A-Z][A-Za-z0-9]*$")
_UPPER_SNAKE_CASE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _to_snake_case(name: str) -> str:
    """CamelCase / mixedCase → snake_case (GetUserData → get_user_data)."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _to_pascal_case(name: str) -> str:
    """snake_case → PascalCase (user_record → UserRecord)."""
    return "".join(part[:1].upper() + part[1:] for part in name.split("_") if part)


def _to_upper_snake_case(name: str) -> str:
    """CamelCase / mixedCase → UPPER_SNAKE_CASE (MaxRetries → MAX_RETRIES)."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper()


@dataclass
class Finding:
    """One review finding on a single added line (or a whole file)."""

    path: str
    line: int  # 0 means the finding applies to the file as a whole
    severity: str  # "error" | "warning" | "info"
    rule: str
    message: str
    suggestion: str = ""


# ---------------------------------------------------------------------------
# Line-based rules (regex over each added line)
# ---------------------------------------------------------------------------

@dataclass
class _LineRule:
    pattern: re.Pattern[str]
    severity: str
    rule: str
    message: str
    suggestion: str


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


SECURITY_RULES: list[_LineRule] = [
    _LineRule(
        _r(r"(?i)\b(password|passwd|api[_-]?key|secret|access[_-]?token)\b\s*=\s*['\"][^'\"]+['\"]"),
        "error", "SEC001",
        "Possible hardcoded credential assigned in added code.",
        "Read it from an environment variable or a secret store instead.",
    ),
    _LineRule(
        _r(r"\beval\s*\("),
        "error", "SEC002",
        "eval() executes arbitrary code from a string.",
        "Parse the input instead (ast.literal_eval, json.loads) or restructure the code.",
    ),
    _LineRule(
        _r(r"\bexec\s*\("),
        "error", "SEC003",
        "exec() executes arbitrary code from a string.",
        "Replace with a direct call or a dispatch table.",
    ),
    _LineRule(
        _r(r"os\.system\s*\(|subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
        "error", "SEC004",
        "Shell command executed with shell=True or os.system().",
        "Pass the command as a list and keep shell=False (the default).",
    ),
    _LineRule(
        _r(r"pickle\.(loads|load)\s*\("),
        "warning", "SEC005",
        "pickle.loads() on untrusted data can run arbitrary code.",
        "Use a safe format (JSON) or only unpickle data you produced yourself.",
    ),
    _LineRule(
        _r(r"yaml\.load\s*\([^)]*\)"),
        "warning", "SEC006",
        "yaml.load() without an explicit safe loader can construct arbitrary objects.",
        "Use yaml.safe_load() unless you genuinely need full YAML tags.",
    ),
    _LineRule(
        _r(r"hashlib\.(md5|sha1)\s*\("),
        "info", "SEC007",
        "MD5/SHA-1 is broken for collision resistance.",
        "Use SHA-256 or better for hashing, especially for passwords or signatures.",
    ),
    _LineRule(
        _r(r"verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False"),
        "error", "SEC008",
        "TLS certificate verification is disabled.",
        "Keep verification on; pin a CA bundle if the endpoint uses a private CA.",
    ),
]

BUG_RULES: list[_LineRule] = [
    _LineRule(
        _r(r"^\s*except\s*:"),
        "warning", "BUG001",
        "Bare except: also swallows KeyboardInterrupt and SystemExit.",
        "Catch the specific exception type you expect.",
    ),
    _LineRule(
        _r(r"^\s*except\s+Exception\s*:\s*$"),
        "info", "BUG002",
        "except Exception: with an empty body hides every failure.",
        "Log the error or handle the specific cases; avoid silent pass.",
    ),
    _LineRule(
        _r(r"(?i)\b(TODO|FIXME|HACK|XXX)\b"),
        "info", "BUG003",
        "TODO/FIXME marker added — track it or fix it before merging.",
        "Turn it into an issue, or resolve it in this PR.",
    ),
    _LineRule(
        _r(r"\.format\s*\(.*\{.*\}.*\)|f['\"].*\{[^}]*\+[^}]*\}"),
        "warning", "BUG004",
        "String built with user data inside what looks like a query or command.",
        "Use parameterised queries / argument lists instead of interpolation.",
    ),
]

STYLE_RULES: list[_LineRule] = [
    _LineRule(
        _r(r".{121,}"),
        "info", "STY001",
        "Line is over 120 characters long.",
        "Split it for readability; long URLs and strings are exempt in review.",
    ),
    _LineRule(
        _r(r"\bprint\s*\("),
        "info", "STY002",
        "print() left in added code.",
        "Use logging (or remove it) so output stays structured in production.",
    ),
    _LineRule(
        _r(r"[ \t]+$"),
        "info", "STY003",
        "Trailing whitespace at the end of the line.",
        "Delete the trailing spaces or tabs — most editors can strip them on save.",
    ),
    _LineRule(
        _r(r"^\t"),
        "info", "STY006",
        "Line is indented with a tab instead of spaces.",
        "Indent with spaces (4 per level in Python) so the code looks the same in every editor.",
    ),
]


def _apply_line_rules(
    changed: ChangedFile, rules: list[_LineRule], category: str
) -> list[Finding]:
    findings: list[Finding] = []
    for added in changed.added:
        for rule in rules:
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


# ---------------------------------------------------------------------------
# Python AST rules (function shape, nesting, mutable defaults)
# ---------------------------------------------------------------------------

def _nesting_depth(node: ast.AST, depth: int = 0) -> int:
    deepest = depth
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            deepest = max(deepest, _nesting_depth(child, depth + 1))
        else:
            deepest = max(deepest, _nesting_depth(child, depth))
    return deepest


def _count_returns(node: ast.AST) -> int:
    """Count return statements in a function, excluding nested functions."""
    count = 0
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(child, ast.Return):
            count += 1
        count += _count_returns(child)
    return count


def _bool_default_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Names of parameters whose default is a bool literal (True/False)."""
    pairs: list[tuple[ast.arg, ast.expr | None]] = []
    if node.args.defaults:
        pairs += list(
            zip(node.args.args[-len(node.args.defaults):], node.args.defaults)
        )
    pairs += [
        (arg, default)
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
        if default is not None
    ]
    return [
        arg.arg
        for arg, default in pairs
        if isinstance(default, ast.Constant) and isinstance(default.value, bool)
    ]


_COMPREHENSION_TYPES = (
    ast.ListComp,
    ast.SetComp,
    ast.DictComp,
    ast.GeneratorExp,
)


def _check_comprehensions_and_lambdas(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Flag nested/over-long comprehensions and lambdas assigned to names.

    Runs over the whole added fragment (not just inside functions), since a
    lambda assignment or a comprehension usually lives at module level.
    A comprehension nested inside another is flagged once, on the outer one.
    """
    findings: list[Finding] = []

    def _walk(node: ast.AST, in_comp: bool = False) -> None:
        if isinstance(node, _COMPREHENSION_TYPES):
            if not in_comp:
                nested = any(
                    isinstance(desc, _COMPREHENSION_TYPES)
                    for desc in ast.walk(node)
                    if desc is not node
                )
                too_many = len(node.generators) > MAX_COMPREHENSION_GENERATORS
                if nested or too_many:
                    if nested and too_many:
                        detail = (
                            f"nests another comprehension and has "
                            f"{len(node.generators)} for-clauses "
                            f"(over {MAX_COMPREHENSION_GENERATORS})"
                        )
                    elif nested:
                        detail = "nests another comprehension"
                    else:
                        detail = (
                            f"has {len(node.generators)} for-clauses "
                            f"(over {MAX_COMPREHENSION_GENERATORS})"
                        )
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "CPL006",
                            f"Comprehension {detail}.",
                            "Rewrite it as a plain loop — it will read far better.",
                        )
                    )
            for child in ast.iter_child_nodes(node):
                _walk(child, True)
            return
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if isinstance(value, ast.Lambda):
                targets = (
                    node.targets
                    if isinstance(node, ast.Assign)
                    else [node.target]
                )
                name = (
                    targets[0].id
                    if targets and isinstance(targets[0], ast.Name)
                    else "?"
                )
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "info",
                        "CPL007",
                        f"Lambda assigned to '{name}' instead of a named function.",
                        "Use a def statement — it gets a proper name and docstring.",
                    )
                )
        for child in ast.iter_child_nodes(node):
            _walk(child, in_comp)

    _walk(tree)
    return findings


def _check_imports(
    tree: ast.AST, changed: ChangedFile, _real, source: str
) -> list[Finding]:
    """Python import rules IMP001–IMP003.

    IMP001 (warning): ``from x import *`` — a wildcard import hides where
    names come from. IMP002 (warning): an imported name that is never used
    anywhere else in the added lines. IMP003 (info): an import statement
    inside a function or class instead of at the top of the module.

    IMP002 is best-effort by design: the review only sees added lines, so
    a name imported here and used in untouched code elsewhere in the file
    would be flagged wrongly. It is skipped entirely when the fragment
    defines ``__all__`` (re-exported names are used by definition).
    """
    findings: list[Finding] = []

    import_nodes: list[ast.AST] = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
    ]

    # IMP001 — wildcard imports.
    for node in import_nodes:
        if isinstance(node, ast.ImportFrom) and any(
            alias.name == "*" for alias in node.names
        ):
            module = node.module or ""
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "IMP001",
                    f"Wildcard import from '{module}' hides where names come from.",
                    "Import the names you need explicitly.",
                )
            )

    # IMP003 — imports inside a function or class body.
    def _walk_scoped(node: ast.AST, nested: bool = False) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            nested = True
        if nested and isinstance(node, (ast.Import, ast.ImportFrom)):
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "info",
                    "IMP003",
                    "Import inside a function or class — keep imports at the top of the module.",
                    "Move it to the top unless the import is genuinely circular or optional.",
                )
            )
        for child in ast.iter_child_nodes(node):
            _walk_scoped(child, nested)

    _walk_scoped(tree)

    # IMP002 — unused imports.
    if "__all__" not in source:
        # Lines covered by an import statement, so a name is not counted
        # as "used" just because it appears in its own import line.
        import_lines: set[int] = set()
        for node in import_nodes:
            start = getattr(node, "lineno", 0)
            end = getattr(node, "end_lineno", 0) or start
            import_lines.update(range(start, end + 1))
        source_lines = source.split("\n")
        rest = "\n".join(
            line for i, line in enumerate(source_lines, start=1)
            if i not in import_lines
        )
        bound: list[tuple[str, int]] = []
        for node in import_nodes:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound.append(
                        (alias.asname or alias.name.split(".")[0],
                         getattr(node, "lineno", 0))
                    )
            else:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    bound.append(
                        (alias.asname or alias.name,
                         getattr(node, "lineno", 0))
                    )
        for name, lineno in bound:
            if not re.search(rf"\b{re.escape(name)}\b", rest):
                findings.append(
                    Finding(
                        changed.path,
                        _real(lineno),
                        "warning",
                        "IMP002",
                        f"Imported name '{name}' is never used in the added code.",
                        "Remove the import, or use the name — dead imports confuse the next reader.",
                    )
                )
    return findings


def _check_naming(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python naming rules NAM001–NAM004 (PEP 8 conventions).

    NAM001 (info): a function or method name that is not snake_case
    (dunder methods such as ``__init__`` are exempt). NAM002 (info): a
    class name that is not PascalCase. NAM003 (info): a module-level
    constant — a name assigned a literal value — that uses mixed case
    instead of UPPER_SNAKE_CASE; plain lowercase module variables are
    left alone, and names starting with an underscore are exempt.
    NAM004 (warning): a name that shadows a Python builtin — a function
    or class name, a parameter, or any assignment / loop / ``with``
    target. Method names inside a class body are exempt from NAM004: a
    method does not shadow the builtin in module scope.
    """
    findings: list[Finding] = []

    def _is_dunder(name: str) -> bool:
        return name.startswith("__") and name.endswith("__")

    # NAM003 — module-level constants in the wrong case.
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None or not isinstance(value, ast.Constant):
            continue
        targets = (
            node.targets
            if isinstance(node, ast.Assign)
            else [node.target]
        )
        for target in targets:
            if not isinstance(target, ast.Name):
                continue
            name = target.id
            if name.startswith("_") or _is_dunder(name):
                continue
            if any(ch.isupper() for ch in name) and not _UPPER_SNAKE_CASE.match(name):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "info",
                        "NAM003",
                        f"Module-level constant '{name}' is not UPPER_SNAKE_CASE.",
                        f"Rename it to '{_to_upper_snake_case(name)}'.",
                    )
                )

    # NAM001 / NAM002 / NAM004 — walk every definition and binding.
    def _walk(node: ast.AST, in_class: bool = False) -> None:
        if isinstance(node, ast.ClassDef):
            if not _PASCAL_CASE.match(node.name):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "info",
                        "NAM002",
                        f"Class name '{node.name}' is not PascalCase.",
                        f"Rename it to '{_to_pascal_case(node.name)}'.",
                    )
                )
            if node.name in _BUILTIN_NAMES:
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "NAM004",
                        f"Class name '{node.name}' shadows the Python builtin '{node.name}'.",
                        "Pick a different name so the builtin stays available.",
                    )
                )
            for child in ast.iter_child_nodes(node):
                _walk(child, True)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not _is_dunder(node.name) and not _SNAKE_CASE.match(node.name):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "info",
                        "NAM001",
                        f"Function name '{node.name}' is not snake_case.",
                        f"Rename it to '{_to_snake_case(node.name)}'.",
                    )
                )
            if not in_class and node.name in _BUILTIN_NAMES:
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "NAM004",
                        f"Function name '{node.name}' shadows the Python builtin '{node.name}'.",
                        "Pick a different name so the builtin stays available.",
                    )
                )
            params = (
                list(node.args.posonlyargs)
                + list(node.args.args)
                + list(node.args.kwonlyargs)
            )
            for arg in params:
                if arg.arg in _BUILTIN_NAMES:
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "NAM004",
                            f"Parameter '{arg.arg}' in '{node.name}' shadows the Python builtin '{arg.arg}'.",
                            "Rename the parameter — shadowing a builtin hides it for the whole function body.",
                        )
                    )
            for arg in (node.args.vararg, node.args.kwarg):
                if arg is not None and arg.arg in _BUILTIN_NAMES:
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "NAM004",
                            f"Parameter '{arg.arg}' in '{node.name}' shadows the Python builtin '{arg.arg}'.",
                            "Rename the parameter — shadowing a builtin hides it for the whole function body.",
                        )
                    )
            for child in ast.iter_child_nodes(node):
                _walk(child, in_class)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            if node.id in _BUILTIN_NAMES:
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "NAM004",
                        f"Name '{node.id}' shadows the Python builtin '{node.id}'.",
                        "Pick a different name so the builtin stays available.",
                    )
                )
        for child in ast.iter_child_nodes(node):
            _walk(child, in_class)

    _walk(tree)
    return findings


def _check_errors(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python error-handling rules ERR001–ERR004 (AST-based).

    ERR001 (warning): an ``except`` handler whose body is only ``pass``
    (or ``...``) — the error is swallowed silently. ERR002 (warning):
    raising a new exception inside an ``except`` handler without
    ``from`` — the original traceback context is lost. ERR003
    (warning): catching ``BaseException`` — it also swallows
    ``KeyboardInterrupt`` and ``SystemExit``. ERR004 (info): a ``try``
    block whose body is only ``pass`` — the ``try`` does nothing.
    """
    findings: list[Finding] = []

    def _is_silent(body: list[ast.stmt]) -> bool:
        if len(body) != 1:
            return False
        stmt = body[0]
        if isinstance(stmt, ast.Pass):
            return True
        return (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is Ellipsis
        )

    def _handler_catches_base(handler: ast.ExceptHandler) -> bool:
        def _names(expr: ast.expr | None) -> list[str]:
            if expr is None:
                return []
            if isinstance(expr, ast.Name):
                return [expr.id]
            if isinstance(expr, ast.Attribute):
                return [expr.attr]
            if isinstance(expr, ast.Tuple):
                names: list[str] = []
                for elt in expr.elts:
                    names.extend(_names(elt))
                return names
            return []

        return "BaseException" in _names(handler.type)

    def _walk_raises(node: ast.AST) -> None:
        """Flag `raise <new>` without `from` inside an except handler.

        Does not descend into nested except handlers (the top-level loop
        visits them separately) or into nested function/class bodies — a
        raise there runs outside the handler's dynamic scope.
        """
        if isinstance(node, ast.ExceptHandler):
            return
        if isinstance(node, ast.Raise):
            if node.exc is not None and node.cause is None:
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "ERR002",
                        "Raising a new exception inside an except handler without 'from' loses the original traceback.",
                        "Chain it explicitly: 'raise NewError(...) from e'.",
                    )
                )
            return
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            return
        for child in ast.iter_child_nodes(node):
            _walk_raises(child)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        # ERR004 — a try block that does nothing.
        if _is_silent(node.body):
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "info",
                    "ERR004",
                    "try block whose body is only 'pass' does nothing.",
                    "Remove the try, or put the fallible code inside it.",
                )
            )
        for handler in node.handlers:
            # ERR001 — a handler that silently swallows the error.
            if _is_silent(handler.body):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(handler, "lineno", 0)),
                        "warning",
                        "ERR001",
                        "except handler silently swallows the error (body is only 'pass').",
                        "Log the error, handle it, or re-raise — silent excepts hide failures.",
                    )
                )
            # ERR003 — catching BaseException.
            if _handler_catches_base(handler):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(handler, "lineno", 0)),
                        "warning",
                        "ERR003",
                        "Catching BaseException also swallows KeyboardInterrupt and SystemExit.",
                        "Catch Exception (or a narrower type) instead.",
                    )
                )
            # ERR002 — raise without `from` inside the handler.
            for stmt in handler.body:
                _walk_raises(stmt)
    return findings


def _dotted_name(node: ast.AST) -> str:
    """Rebuild the dotted name of a call target (``subprocess.run``)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


_SUBPROCESS_FUNCS = frozenset({
    "run", "call", "Popen", "check_output", "check_call", "getoutput",
})
_RANDOM_FUNCS = frozenset({
    "random", "randint", "randrange", "choice", "choices", "uniform",
    "sample",
})
_SENSITIVE_NAME = re.compile(
    r"(?i)(token|passwd|password|secret|api[_-]?key|otp|nonce)"
)


def _check_security(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python security rules SEC101–SEC105 (AST-based).

    SEC101 (warning): a ``subprocess`` call given a string command
    instead of a list — a string is handed to the shell as soon as
    ``shell=True`` is added, and on POSIX a string with ``shell=False``
    is treated as the program name. ``os.popen()`` always runs through
    the shell, so any call to it is flagged. A variable holding the
    command cannot be checked (its type is unknown), so only literal
    strings and f-strings are flagged. SEC102 (warning): the ``random``
    module used to build a token, password, secret or one-time code —
    ``random`` is not cryptographically secure. Only a direct
    ``random.*`` call assigned to a sensitively-named variable is
    flagged. SEC103 (warning): an ``assert`` statement outside test
    code — asserts are stripped entirely when Python runs with ``-O``.
    SEC104 (warning): ``tempfile.mktemp()`` — the filename is
    predictable, so another process can create it first. SEC105
    (warning): ``os.chmod()`` with a world-writable mode (any constant
    mode with the ``0o002`` bit set, e.g. ``0o777``).
    """
    findings: list[Finding] = []

    # SEC103 — asserts in non-test code.
    in_test_file = bool(_TEST_PATH.search(changed.path))
    if not in_test_file:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "SEC103",
                        "assert used outside test code — asserts are stripped with python -O.",
                        "Raise a proper exception or validate explicitly instead of assert.",
                    )
                )

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            targets = None
            value = None

        # SEC102 — random.* assigned to a sensitively-named variable.
        if (
            targets is not None
            and value is not None
            and isinstance(value, ast.Call)
        ):
            called = _dotted_name(value.func)
            if called.startswith("random.") and called.split(".")[-1] in _RANDOM_FUNCS:
                for target in targets:
                    if isinstance(target, ast.Name) and _SENSITIVE_NAME.search(target.id):
                        findings.append(
                            Finding(
                                changed.path,
                                _real(getattr(node, "lineno", 0)),
                                "warning",
                                "SEC102",
                                f"'{target.id}' is built with random — random is not cryptographically secure.",
                                "Use the secrets module (secrets.token_hex, secrets.choice) for tokens and passwords.",
                            )
                        )
                        break

        if not isinstance(node, ast.Call):
            continue
        called = _dotted_name(node.func)

        # SEC101 — subprocess with a string command, or os.popen().
        if called.startswith("subprocess.") and called.split(".")[-1] in _SUBPROCESS_FUNCS:
            if node.args:
                first = node.args[0]
                is_string = (
                    isinstance(first, ast.JoinedStr)
                    or (
                        isinstance(first, ast.Constant)
                        and isinstance(first.value, str)
                    )
                )
                if is_string:
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "SEC101",
                            f"subprocess.{called.split('.')[-1]}() called with a string command instead of a list.",
                            "Pass the command as a list (['ls', '-la']) and keep shell=False.",
                        )
                    )
        elif called == "os.popen":
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "SEC101",
                    "os.popen() runs the command through the shell.",
                    "Use subprocess.run() with a list of arguments instead.",
                )
            )

        # SEC104 — tempfile.mktemp().
        if called == "tempfile.mktemp":
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "SEC104",
                    "tempfile.mktemp() returns a predictable filename another process can create first.",
                    "Use tempfile.NamedTemporaryFile() instead.",
                )
            )

        # SEC105 — os.chmod() with a world-writable mode.
        if called == "os.chmod" and len(node.args) >= 2:
            mode = node.args[1]
            if (
                isinstance(mode, ast.Constant)
                and isinstance(mode.value, int)
                and mode.value & 0o002
            ):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "SEC105",
                        f"os.chmod() with mode {oct(mode.value)} makes the file world-writable.",
                        "Use the least permissive mode the file needs (e.g. 0o600 for private data).",
                    )
                )

    return findings


def _check_bugs(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python bug rules BUG101–BUG105 (AST-based).

    BUG101 (warning): code after ``return`` / ``raise`` / ``break`` /
    ``continue`` in the same block — it never runs. Only statements in
    the same body list are checked, so code after an ``if`` that returns
    is left alone (the ``if`` may not run). BUG102 (warning): a dict
    literal with the same constant key twice — the earlier value is
    silently overwritten. Only constant keys are compared, and keys of
    different types (``1`` vs ``True``) are not treated as duplicates.
    BUG103 (warning): ``is`` / ``is not`` used with a literal number,
    string or bytes value — identity is not value equality, so use
    ``==``; ``is None`` / ``is True`` are left alone. BUG104 (warning):
    a constant condition in ``if`` / ``while`` — the branch always
    runs or never runs. ``while True`` (and other truthy constants in
    ``while``) are exempt: they are the standard infinite-loop idiom;
    only a falsy constant in ``while`` (``while False``) is flagged as
    a dead loop. BUG105 (warning): comparing a variable to itself
    (``x == x``) — almost certainly a typo, since it is always True
    (``!=`` always False).
    """
    findings: list[Finding] = []

    # BUG101 — unreachable code after a terminator in the same block.
    _TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    def _scan_bodies(node: ast.AST) -> None:
        for attr in ("body", "orelse", "finalbody"):
            stmts = getattr(node, attr, None)
            if (
                isinstance(stmts, list)
                and stmts
                and all(isinstance(stmt, ast.stmt) for stmt in stmts)
            ):
                terminated = False
                for stmt in stmts:
                    if terminated:
                        findings.append(
                            Finding(
                                changed.path,
                                _real(getattr(stmt, "lineno", 0)),
                                "warning",
                                "BUG101",
                                "Code after 'return' / 'raise' / 'break' / 'continue' in this block never runs.",
                                "Move it before the terminator, or into the branch that actually runs.",
                            )
                        )
                    if isinstance(stmt, _TERMINATORS):
                        terminated = True
        for child in ast.iter_child_nodes(node):
            _scan_bodies(child)

    _scan_bodies(tree)

    for node in ast.walk(tree):
        # BUG102 — duplicate key in a dict literal.
        if isinstance(node, ast.Dict):
            seen: dict[tuple[str, str], int] = {}
            for key in node.keys:
                if key is None or not isinstance(key, ast.Constant):
                    continue
                marker = (type(key.value).__name__, repr(key.value))
                if marker in seen:
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(key, "lineno", 0)),
                            "warning",
                            "BUG102",
                            f"Duplicate key {key.value!r} in a dict literal — the earlier value is silently overwritten.",
                            "Remove the duplicate, or rename the key you meant.",
                        )
                    )
                else:
                    seen[marker] = getattr(key, "lineno", 0)
            continue

        # BUG103 — `is` / `is not` with a literal. BUG105 — a variable
        # compared to itself. Both read the same Compare node.
        if isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for op, left, right in zip(node.ops, operands, operands[1:]):
                if not isinstance(op, (ast.Is, ast.IsNot)):
                    continue
                literal: object = None
                for side in (left, right):
                    if (
                        isinstance(side, ast.Constant)
                        and isinstance(
                            side.value, (int, float, complex, str, bytes)
                        )
                        and not isinstance(side.value, bool)
                    ):
                        literal = side.value
                        break
                if literal is not None:
                    verb = "is" if isinstance(op, ast.Is) else "is not"
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "BUG103",
                            f"Comparing with '{verb}' to the literal {literal!r} — identity is not value equality.",
                            "Use '==' / '!=' to compare values; 'is' only checks that two names point at the same object.",
                        )
                    )
                    break
            for op, left, right in zip(node.ops, operands, operands[1:]):
                if not isinstance(op, (ast.Eq, ast.NotEq)):
                    continue
                if (
                    isinstance(left, ast.Name)
                    and isinstance(right, ast.Name)
                    and left.id == right.id
                ):
                    verb = "==" if isinstance(op, ast.Eq) else "!="
                    outcome = "True" if isinstance(op, ast.Eq) else "False"
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "BUG105",
                            f"Comparing '{left.id}' to itself with '{verb}' — always {outcome}.",
                            "Check the variable names — one side is probably a typo.",
                        )
                    )
                    break
            continue

        # BUG104 — constant condition in `if` / `while`.
        if isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
            outcome = "always runs" if node.test.value else "never runs"
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "BUG104",
                    f"'if' condition is the constant {node.test.value!r}, so this branch {outcome}.",
                    "Replace the constant with the real condition, or remove the dead branch.",
                )
            )
        elif (
            isinstance(node, ast.While)
            and isinstance(node.test, ast.Constant)
            and not node.test.value
        ):
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "BUG104",
                    f"'while' condition is the constant {node.test.value!r}, so this loop never runs.",
                    "Replace the constant with the real condition, or remove the dead loop.",
                )
            )

    return findings


def _check_performance(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python performance rules PERF101–PERF105 (AST-based).

    PERF101 (warning): ``name += ...`` on a string inside a loop — each
    ``+=`` builds a whole new string, so the loop is quadratic; collect
    the parts in a list and ``''.join(...)`` once at the end. Only names
    assigned a string literal in the same function are flagged, so
    ``total += 1`` on a number is left alone. PERF102 (warning):
    ``range(len(x))`` — iterate the sequence directly, or use
    ``enumerate(x)`` when the index is needed. PERF103 (warning):
    ``x in [a, b, ...]`` — a membership test against a list literal
    scans the whole list on every check; use a set or frozenset for
    repeated lookups. Only list literals are flagged, not tuples or
    variables. PERF104 (warning): a loop whose body is only
    ``name.append(...)`` where ``name`` was assigned ``[]`` in the same
    function — the loop is a list comprehension in disguise. A list
    passed in from outside, or a loop doing more than appending, is
    left alone. PERF105 (warning): ``for k in d.keys():`` — iterating
    a dict already yields its keys, so ``.keys()`` is redundant.
    """
    findings: list[Finding] = []

    # PERF102 / PERF103 / PERF105 — single-node checks.
    for node in ast.walk(tree):
        # PERF102 — range(len(x)).
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "range"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Call)
            and isinstance(node.args[0].func, ast.Name)
            and node.args[0].func.id == "len"
            and len(node.args[0].args) == 1
        ):
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "PERF102",
                    "range(len(x)) — iterate the sequence directly instead of indexing it.",
                    "Use 'for item in x:' or 'for i, item in enumerate(x):' when the index is needed.",
                )
            )
            continue

        # PERF103 — membership test against a list literal.
        if isinstance(node, ast.Compare):
            for op, comparator in zip(node.ops, node.comparators):
                if isinstance(op, (ast.In, ast.NotIn)) and isinstance(
                    comparator, ast.List
                ):
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "PERF103",
                            "Membership test against a list literal scans the whole list on every check.",
                            "Use a set or frozenset for repeated lookups, e.g. {'alice', 'bob'}.",
                        )
                    )
                    break
            continue

        # PERF105 — for k in d.keys():.
        if isinstance(node, ast.For):
            it = node.iter
            if (
                isinstance(it, ast.Call)
                and isinstance(it.func, ast.Attribute)
                and it.func.attr == "keys"
                and not it.args
                and not it.keywords
            ):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "PERF105",
                        "Iterating d.keys() — iterating the dict itself already yields its keys.",
                        "Write 'for k in d:' instead.",
                    )
                )

    # PERF101 / PERF104 — per-function, need scope info (which names
    # hold a string, which hold a fresh empty list).
    def _iter_func_nodes(func: ast.AST):
        """Yield nodes in a function body, not descending into nested defs."""
        stack = list(ast.iter_child_nodes(func))
        while stack:
            node = stack.pop()
            yield node
            if isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
            ):
                continue
            stack.extend(ast.iter_child_nodes(node))

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        string_names: set[str] = set()
        list_names: set[str] = set()
        for node in _iter_func_nodes(func):
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            ):
                target = node.targets[0].id
                if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, str
                ):
                    string_names.add(target)
                elif isinstance(node.value, ast.List) and not node.value.elts:
                    list_names.add(target)

        def _visit(node: ast.AST, in_loop: bool) -> None:
            if (
                isinstance(
                    node,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.ClassDef,
                        ast.Lambda,
                    ),
                )
                and node is not func
            ):
                return
            now_in_loop = in_loop or isinstance(node, (ast.For, ast.While))
            # PERF104 — loop body is a single append to a fresh list.
            if isinstance(node, (ast.For, ast.While)) and len(node.body) == 1:
                stmt = node.body[0]
                if isinstance(stmt, ast.Expr) and isinstance(
                    stmt.value, ast.Call
                ):
                    call = stmt.value
                    if (
                        isinstance(call.func, ast.Attribute)
                        and call.func.attr == "append"
                        and isinstance(call.func.value, ast.Name)
                        and call.func.value.id in list_names
                        and len(call.args) == 1
                    ):
                        findings.append(
                            Finding(
                                changed.path,
                                _real(getattr(stmt, "lineno", 0)),
                                "warning",
                                "PERF104",
                                f"Loop only appends to '{call.func.value.id}' — this is a list comprehension in disguise.",
                                f"Write \"{call.func.value.id} = [<expr> for ... in ...]\" instead.",
                            )
                        )
            # PERF101 — string += inside a loop.
            if (
                isinstance(node, ast.AugAssign)
                and isinstance(node.op, ast.Add)
                and isinstance(node.target, ast.Name)
                and node.target.id in string_names
                and now_in_loop
            ):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "PERF101",
                        f"String concatenation with '+=' on '{node.target.id}' inside a loop is quadratic.",
                        "Collect the parts in a list and call ''.join(...) once at the end.",
                    )
                )
            for child in ast.iter_child_nodes(node):
                _visit(child, now_in_loop)

        _visit(func, False)

    return findings


def _check_docs(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python documentation rules DOC101–DOC105 (AST-based).

    DOC101 (info): a public function or method without a docstring —
    readers (and tools) cannot tell what it does without reading the
    body. DOC102 (info): a public class without a docstring. DOC103
    (warning): a docstring that is empty or only whitespace — it
    claims to document the code and says nothing. DOC104 (info): a
    docstring whose first line does not end with a full stop, ``!``
    or ``?`` — the summary line should be a complete sentence.
    DOC105 (warning): a docstring containing a TODO / FIXME / XXX
    marker — the note belongs in the tracker, not in the docs users
    read. Best-effort limits: private and dunder names are exempt
    (implementation details), as are ``test_*`` functions and
    ``Test*`` classes, which are self-documenting by convention; only
    the first line is checked for DOC104, so multi-sentence summaries
    are left alone.
    """
    findings: list[Finding] = []

    def _docstring(node: ast.AST) -> tuple[str | None, int]:
        """Return (docstring text, its line) or (None, 0)."""
        body = getattr(node, "body", None)
        if not body:
            return None, 0
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            return first.value.value, getattr(first, "lineno", 0)
        return None, 0

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith(("_", "test_")):
                continue
            missing_rule = "DOC101"
            label = f"function '{node.name}'"
        elif isinstance(node, ast.ClassDef):
            if node.name.startswith(("_", "Test")):
                continue
            missing_rule = "DOC102"
            label = f"class '{node.name}'"
        else:
            continue
        text, doc_line = _docstring(node)
        if text is None:
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "info",
                    missing_rule,
                    f"Public {label} has no docstring.",
                    "Add a one-line summary of what it does and what it represents.",
                )
            )
            continue
        if not text.strip():
            findings.append(
                Finding(
                    changed.path,
                    _real(doc_line),
                    "warning",
                    "DOC103",
                    f"Docstring of '{node.name}' is empty.",
                    "Write a one-line summary, or remove the empty docstring.",
                )
            )
            continue
        first_line = text.strip().splitlines()[0].strip()
        if not first_line.endswith((".", "!", "?")):
            findings.append(
                Finding(
                    changed.path,
                    _real(doc_line),
                    "info",
                    "DOC104",
                    f"Docstring of '{node.name}' does not end its first line with a full stop.",
                    "End the summary line with a full stop.",
                )
            )
        if re.search(r"\b(TODO|FIXME|XXX)\b", text, re.IGNORECASE):
            findings.append(
                Finding(
                    changed.path,
                    _real(doc_line),
                    "warning",
                    "DOC105",
                    f"Docstring of '{node.name}' contains a TODO/FIXME marker.",
                    "Move the note to the issue tracker and keep the docstring for users.",
                )
            )

    return findings


_DEPRECATED_TYPING = {"List", "Dict", "Set", "Tuple", "FrozenSet", "Type"}


def _check_typing(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python type-hint rules TYP101–TYP105 (AST-based).

    TYP101 (info): a public function or method without a return type
    annotation — callers cannot tell what it gives back without reading
    the body. TYP102 (info): a public function or method with an
    unannotated parameter — ``self`` and ``cls`` are exempt. TYP103
    (warning): a bare ``Any`` used as an annotation — it switches the
    type checker off for that value. TYP104 (info): a deprecated
    ``typing`` generic (``List``, ``Dict``, ``Set``, ``Tuple``,
    ``FrozenSet``, ``Type``) — the builtin generics (``list``,
    ``dict``, ...) have done the same job since Python 3.9. TYP105
    (warning): a function annotated ``-> None`` that returns a value —
    the annotation and the code disagree. Best-effort limits: private,
    dunder and ``test_*`` functions are exempt from TYP101/TYP102, as
    are stub bodies (``pass`` / ``...`` only) and ``@overload`` /
    ``@abstractmethod`` definitions; TYP104 only recognises the bare
    ``List`` / ``Dict`` / ... spellings when the same fragment imports
    them from ``typing`` (the ``typing.List`` spelling is always
    recognised); TYP105 ignores ``return`` statements inside nested
    functions.
    """
    findings: list[Finding] = []

    # Bare typing generics imported in this fragment, e.g. List in
    # "from typing import List" — only those names are treated as the
    # deprecated aliases when they appear as annotations.
    imported_typing: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "typing":
            for alias in node.names:
                if alias.name in _DEPRECATED_TYPING:
                    imported_typing.add(alias.name)

    def _is_stub(node) -> bool:
        """True for pass/...-only bodies and overload/abstract defs."""

        def _is_pass_or_ellipsis(stmt: ast.stmt) -> bool:
            if isinstance(stmt, ast.Pass):
                return True
            return (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and stmt.value.value is Ellipsis
            )

        if node.body and all(_is_pass_or_ellipsis(s) for s in node.body):
            return True
        for dec in node.decorator_list:
            name = ""
            if isinstance(dec, ast.Name):
                name = dec.id
            elif isinstance(dec, ast.Attribute):
                name = dec.attr
            elif isinstance(dec, ast.Call):
                func = dec.func
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    name = func.attr
            if name in ("overload", "abstractmethod"):
                return True
        return False

    def _check_annotation(ann: ast.expr) -> None:
        """Flag Any (TYP103) and deprecated typing generics (TYP104)."""
        for sub in ast.walk(ann):
            if isinstance(sub, ast.Name) and sub.id == "Any":
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(sub, "lineno", 0)),
                        "warning",
                        "TYP103",
                        "Bare 'Any' annotation switches the type checker off.",
                        "Use a real type, or a precise 'object' / union, instead.",
                    )
                )
            elif (
                isinstance(sub, ast.Attribute)
                and isinstance(sub.value, ast.Name)
                and sub.value.id == "typing"
                and sub.attr in _DEPRECATED_TYPING
            ):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(sub, "lineno", 0)),
                        "info",
                        "TYP104",
                        f"'typing.{sub.attr}' is deprecated — use the builtin '{sub.attr.lower()}' generic instead.",
                        f"Write '{sub.attr.lower()}[...]' instead of 'typing.{sub.attr}[...]'.",
                    )
                )
            elif isinstance(sub, ast.Name) and sub.id in imported_typing:
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(sub, "lineno", 0)),
                        "info",
                        "TYP104",
                        f"'{sub.id}' from typing is deprecated — use the builtin '{sub.id.lower()}' generic instead.",
                        f"Write '{sub.id.lower()}[...]' instead of '{sub.id}[...]'.",
                    )
                )

    def _value_return_lines(node) -> list[int]:
        """Line numbers of 'return <value>' in this function only."""
        lines: list[int] = []

        def _visit(child: ast.AST) -> None:
            if (
                isinstance(
                    child,
                    (
                        ast.FunctionDef,
                        ast.AsyncFunctionDef,
                        ast.ClassDef,
                        ast.Lambda,
                    ),
                )
                and child is not node
            ):
                return
            if isinstance(child, ast.Return) and child.value is not None:
                if not (
                    isinstance(child.value, ast.Constant)
                    and child.value.value is None
                ):
                    lines.append(getattr(child, "lineno", 0))
            for grand in ast.iter_child_nodes(child):
                _visit(grand)

        _visit(node)
        return lines

    def _flag_unannotated(node, arg: ast.arg) -> None:
        findings.append(
            Finding(
                changed.path,
                _real(getattr(node, "lineno", 0)),
                "info",
                "TYP102",
                f"Parameter '{arg.arg}' of '{node.name}' has no type annotation.",
                f"Annotate '{arg.arg}' with its type.",
            )
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and node.annotation is not None:
            _check_annotation(node.annotation)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Annotations on this function's own signature.
        for arg in (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        ):
            if arg.annotation is not None:
                _check_annotation(arg.annotation)
        for extra in (node.args.vararg, node.args.kwarg):
            if extra is not None and extra.annotation is not None:
                _check_annotation(extra.annotation)
        if node.returns is not None:
            _check_annotation(node.returns)
        # TYP105 — -> None but returns a value.
        if isinstance(node.returns, ast.Constant) and node.returns.value is None:
            for lineno in _value_return_lines(node):
                findings.append(
                    Finding(
                        changed.path,
                        _real(lineno),
                        "warning",
                        "TYP105",
                        f"Function '{node.name}' is annotated '-> None' but returns a value.",
                        "Return nothing, or change the annotation to the value's type.",
                    )
                )
        # TYP101 / TYP102 — public, non-stub functions only.
        if node.name.startswith(("_", "test_")) or _is_stub(node):
            continue
        if node.returns is None:
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "info",
                    "TYP101",
                    f"Public function '{node.name}' has no return type annotation.",
                    "Add a return annotation so callers know what it gives back.",
                )
            )
        params = list(node.args.posonlyargs) + list(node.args.args)
        for index, arg in enumerate(params):
            if index == 0 and arg.arg in ("self", "cls"):
                continue
            if arg.annotation is None:
                _flag_unannotated(node, arg)
        for arg in list(node.args.kwonlyargs):
            if arg.annotation is None:
                _flag_unannotated(node, arg)
        for extra in (node.args.vararg, node.args.kwarg):
            if extra is not None and extra.annotation is None:
                _flag_unannotated(node, extra)

    return findings


def _check_style(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python style rules STY004–STY005 (AST-based).

    STY004 (warning): two or more statements on one line, separated by
    ``;`` — the statements share a line number in the AST but sit at
    different columns. STY005 (warning): comparing a value to a
    singleton (``None``, ``True``, ``False``) with ``==`` or ``!=``
    instead of ``is`` / ``is not``.
    """
    findings: list[Finding] = []

    # STY004 — statements sharing a line.
    flagged_lines: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or len(body) < 2:
            continue
        by_line: dict[int, int] = {}
        for stmt in body:
            lineno = getattr(stmt, "lineno", 0)
            by_line[lineno] = by_line.get(lineno, 0) + 1
        for lineno, count in by_line.items():
            if count > 1 and lineno not in flagged_lines:
                flagged_lines.add(lineno)
                findings.append(
                    Finding(
                        changed.path,
                        _real(lineno),
                        "warning",
                        "STY004",
                        f"{count} statements on one line, separated by ';'.",
                        "Put each statement on its own line — it reads far better.",
                    )
                )

    # STY005 — == / != against a singleton.
    _SINGLETONS = (None, True, False)

    def _is_singleton(expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Constant):
            for value in _SINGLETONS:
                if expr.value is value:
                    return repr(value)
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        for op, comparator in zip(node.ops, node.comparators):
            if not isinstance(op, (ast.Eq, ast.NotEq)):
                continue
            name = _is_singleton(node.left) or _is_singleton(comparator)
            if name is None:
                continue
            verb = "==" if isinstance(op, ast.Eq) else "!="
            replacement = "is" if isinstance(op, ast.Eq) else "is not"
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "STY005",
                    f"Comparison to {name} with '{verb}' — use '{replacement}' instead.",
                    f"Singletons are compared by identity: 'x {replacement} {name}'.",
                )
            )
            break

    return findings


def _check_python_ast(changed: ChangedFile) -> list[Finding]:
    """Run AST checks on the added lines of a Python file.

    The added lines are stitched together and parsed as a module; if the
    fragment is not valid Python (e.g. half a function), the check is
    skipped instead of failing the whole review.
    """
    if not changed.path.endswith(".py"):
        return []
    source = "\n".join(line.text for line in changed.added)
    if not source.strip():
        return []
    # Map fragment line numbers (1-based in the stitched source) back to the
    # real line numbers in the new file, so findings point at the right place.
    real_lineno = [line.lineno for line in changed.added]

    def _real(fragment_lineno: int) -> int:
        if 1 <= fragment_lineno <= len(real_lineno):
            return real_lineno[fragment_lineno - 1]
        return 0

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = _real(getattr(node, "lineno", 0))
        end = _real(getattr(node, "end_lineno", 0) or 0) or start
        span = end - start + 1
        if span > MAX_FUNCTION_LINES:
            findings.append(
                Finding(changed.path, start, "warning", "CPL001",
                        f"Function '{node.name}' is {span} lines long (over {MAX_FUNCTION_LINES}).",
                        "Split it into smaller helpers with one job each.")
            )
        arg_count = len(node.args.args) + len(node.args.kwonlyargs)
        if arg_count > MAX_FUNCTION_ARGS:
            findings.append(
                Finding(changed.path, start, "info", "CPL002",
                        f"Function '{node.name}' takes {arg_count} arguments (over {MAX_FUNCTION_ARGS}).",
                        "Group related arguments into a dataclass or config object.")
            )
        depth = _nesting_depth(node)
        if depth > MAX_NESTING_DEPTH:
            findings.append(
                Finding(changed.path, start, "warning", "CPL003",
                        f"Function '{node.name}' nests {depth} levels deep (over {MAX_NESTING_DEPTH}).",
                        "Extract the inner branches into guard clauses or helpers.")
            )
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                findings.append(
                    Finding(changed.path, start, "warning", "BUG005",
                            f"Mutable default argument in '{node.name}' is shared across calls.",
                            "Use None as the default and create the container inside the function.")
                )
                break
        returns = _count_returns(node)
        if returns > MAX_FUNCTION_RETURNS:
            findings.append(
                Finding(changed.path, start, "warning", "CPL004",
                        f"Function '{node.name}' has {returns} return statements (over {MAX_FUNCTION_RETURNS}).",
                        "Return early with guard clauses, or split the branches into helpers.")
            )
        for param in _bool_default_params(node):
            findings.append(
                Finding(changed.path, start, "info", "CPL005",
                        f"Boolean flag parameter '{param}' in '{node.name}' changes its behaviour from the call site.",
                        "Split it into two functions, or pass an enum / strategy object instead.")
            )
    findings.extend(_check_comprehensions_and_lambdas(tree, changed, _real))
    findings.extend(_check_imports(tree, changed, _real, source))
    findings.extend(_check_naming(tree, changed, _real))
    findings.extend(_check_style(tree, changed, _real))
    findings.extend(_check_errors(tree, changed, _real))
    findings.extend(_check_security(tree, changed, _real))
    findings.extend(_check_bugs(tree, changed, _real))
    findings.extend(_check_performance(tree, changed, _real))
    findings.extend(_check_docs(tree, changed, _real))
    findings.extend(_check_typing(tree, changed, _real))
    return findings


# ---------------------------------------------------------------------------
# PR-level rules
# ---------------------------------------------------------------------------

_TEST_PATH = re.compile(r"(^|/)tests?/|test_.*\.py$|_test\.(py|js|ts|go)$|\.test\.(js|ts)$")
_SOURCE_PATH = re.compile(r"\.(py|js|ts|go|java|rb)$")


def _check_missing_tests(files: list[ChangedFile]) -> list[Finding]:
    """Flag PRs that change source files without touching any test file."""
    changed_sources = [f.path for f in files if _SOURCE_PATH.search(f.path)]
    if not changed_sources:
        return []
    if any(_TEST_PATH.search(f.path) for f in files):
        return []
    return [
        Finding(
            path=changed_sources[0],
            line=0,
            severity="warning",
            rule="TST001",
            message="Source files changed but no test file was touched in this PR.",
            suggestion="Add or update a test covering the new behaviour, or explain why none is needed.",
        )
    ]


def review_files(files: list[ChangedFile], ignore_rules: set[str] | None = None) -> list[Finding]:
    """Run every rule over the changed files and return all findings.

    ``ignore_rules`` is an optional set of rule ids (case-insensitive)
    to skip — for rules a repo has deliberately decided not to enforce,
    e.g. ``{"STY002"}`` to allow ``print()`` calls. Unknown ids are
    ignored harmlessly.
    """
    # Lazy import: checks_js needs Finding from this module.
    from .checks_js import check_js

    ignored = {rule.strip().upper() for rule in (ignore_rules or set()) if rule.strip()}
    findings: list[Finding] = []
    for changed in files:
        if changed.path.endswith((".md", ".txt", ".rst", ".json", ".yml", ".yaml", ".toml", ".lock")):
            continue
        findings.extend(_apply_line_rules(changed, SECURITY_RULES, "security"))
        findings.extend(_apply_line_rules(changed, BUG_RULES, "bugs"))
        findings.extend(_apply_line_rules(changed, STYLE_RULES, "style"))
        findings.extend(_check_python_ast(changed))
        findings.extend(check_js(changed))
    findings.extend(_check_missing_tests(files))
    findings = [f for f in findings if f.rule.upper() not in ignored]
    severity_rank = {"error": 0, "warning": 1, "info": 2}
    return sorted(findings, key=lambda f: (severity_rank[f.severity], f.path, f.line))
