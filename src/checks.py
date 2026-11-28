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


def _check_async(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python async/concurrency rules ASC101–ASC105 (AST-based).

    ASC101 (warning): ``time.sleep(...)`` inside an ``async def`` — it blocks
    the whole event loop; use ``await asyncio.sleep(...)`` instead. Both the
    ``time.sleep`` spelling and a bare ``sleep`` imported from ``time`` are
    recognised. ASC102 (warning): calling an async function without
    ``await`` — the call builds a coroutine object that never runs. Only
    async functions defined in the same fragment are recognised (plus
    ``asyncio.sleep``). A call passed to ``asyncio.create_task`` /
    ``ensure_future`` / ``gather`` / ``run_until_complete`` / ``wait`` is
    exempt — those schedule the coroutine on purpose. ASC103 (info): an
    ``async def`` that never awaits anything — it is probably a plain
    function wearing ``async``. Stub bodies (``pass`` / ``...`` only) and
    async generators (a ``yield`` in the body) are exempt. ASC104 (warning):
    ``loop.run_until_complete(...)`` inside an ``async def`` — the loop is
    already running, so this raises RuntimeError. ASC105 (warning): a bare
    ``asyncio.create_task(...)`` statement whose result is discarded — the
    task can be garbage-collected mid-flight and its exceptions are
    silently lost; keep the task object. Best-effort limits: a call through
    another name (e.g. an async function imported from elsewhere) is not
    recognised by ASC102, and a blocking call inside a sync function nested
    in an async one is not flagged by ASC101/ASC104.
    """
    findings: list[Finding] = []

    async_names: set[str] = set()
    time_sleep_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef):
            async_names.add(node.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "time":
            for alias in node.names:
                if alias.name == "sleep":
                    time_sleep_names.add(alias.asname or alias.name)

    _SCHEDULERS = (
        "create_task",
        "ensure_future",
        "gather",
        "run_until_complete",
        "wait",
        "as_completed",
    )

    def _is_async_call(node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name) and func.id in async_names:
            return True
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "asyncio"
            and func.attr == "sleep"
        )

    def _is_scheduler_call(node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute):
            return func.attr in _SCHEDULERS
        return isinstance(func, ast.Name) and func.id in _SCHEDULERS

    def _is_time_sleep(node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id in time_sleep_names
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "time"
            and func.attr == "sleep"
        )

    def _await_or_yield(node: ast.AST) -> tuple[bool, bool]:
        """(has await, has yield) in this function, excluding nested defs."""
        found = [False, False]

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
            if isinstance(child, ast.Await):
                found[0] = True
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                found[1] = True
            for grand in ast.iter_child_nodes(child):
                _visit(grand)

        _visit(node)
        return found[0], found[1]

    def _is_stub_body(node) -> bool:
        def _pass_or_ellipsis(stmt: ast.stmt) -> bool:
            if isinstance(stmt, ast.Pass):
                return True
            return (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and stmt.value.value is Ellipsis
            )

        body = node.body
        # A leading docstring does not make a stub real code.
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        return bool(body) and all(_pass_or_ellipsis(s) for s in body)

    # ASC103 — async defs that never await.
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        if _is_stub_body(node):
            continue
        has_await, has_yield = _await_or_yield(node)
        if not has_await and not has_yield:
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "info",
                    "ASC103",
                    f"Async function '{node.name}' never awaits anything.",
                    "Make it a plain 'def', or await the async work it does.",
                )
            )

    # ASC101 / ASC102 / ASC104 / ASC105 — walk with async context.
    def _visit(node: ast.AST, in_async: bool, ancestors: tuple[ast.AST, ...]) -> None:
        if isinstance(node, ast.AsyncFunctionDef):
            in_async = True
        elif isinstance(node, ast.FunctionDef):
            in_async = False
        if in_async:
            if isinstance(node, ast.Call):
                if _is_time_sleep(node):
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "ASC101",
                            "time.sleep() inside an async function blocks the whole event loop.",
                            "Use 'await asyncio.sleep(...)' instead.",
                        )
                    )
                elif _is_async_call(node) and not any(
                    isinstance(a, ast.Await) for a in ancestors
                ) and not any(
                    isinstance(a, ast.Call) and _is_scheduler_call(a)
                    for a in ancestors
                ):
                    func = node.func
                    name = (
                        func.id
                        if isinstance(func, ast.Name)
                        else f"asyncio.{func.attr}"
                    )
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "ASC102",
                            f"Async function '{name}' called without 'await' — the coroutine never runs.",
                            f"Await it ('await {name}(...)'), or schedule it with asyncio.create_task.",
                        )
                    )
                elif (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run_until_complete"
                ):
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "ASC104",
                            "run_until_complete() inside an async function — the event loop is already running.",
                            "Await the coroutine directly instead of starting the loop again.",
                        )
                    )
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if (
                    isinstance(call.func, ast.Attribute)
                    and call.func.attr == "create_task"
                ):
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "ASC105",
                            "asyncio.create_task() result is discarded — the task can be dropped mid-flight.",
                            "Keep the task object ('task = asyncio.create_task(...)') and await it.",
                        )
                    )
        for child in ast.iter_child_nodes(node):
            _visit(child, in_async, ancestors + (node,))

    _visit(tree, False, ())
    return findings


def _check_idioms(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python idiom rules IDM101–IDM105 (AST-based).

    IDM101 (warning): ``open(...)`` called outside a ``with`` statement —
    the file handle is never closed explicitly, so it leaks until the
    garbage collector gets to it; use ``with open(...) as f:`` instead.
    Only the direct ``with open(...) as f:`` form is recognised, so
    ``f = open(...); with f:`` is still flagged (best-effort). IDM102
    (warning): ``type(x) == T`` / ``is`` / ``!=`` / ``is not`` — this
    compares the exact type and misses subclasses; use
    ``isinstance(x, T)`` instead. IDM103 (info): ``len(x) == 0`` /
    ``!= 0`` / ``> 0`` — compare truthiness instead (``not x`` / ``x``).
    IDM104 (info): old-style ``%`` string formatting (``"%s" % value``)
    — prefer an f-string or ``str.format(...)``. IDM105 (info):
    ``x in d.keys()`` / ``x not in d.keys()`` — membership in a dict
    already tests its keys, so ``.keys()`` is redundant. Best-effort
    limits: only the bare ``open`` / ``type`` / ``len`` names are
    recognised (an alias such as ``from builtins import open as o``
    is not), and IDM101 does not track a handle opened earlier and
    closed later by hand.
    """
    findings: list[Finding] = []

    def _is_open_call(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
        )

    def _is_len_call(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "len"
            and len(node.args) == 1
        )

    def _is_zero(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Constant)
            and type(node.value) is int
            and node.value == 0
        )

    # IDM101 — open() calls that are a context expression of a with
    # statement are fine; every other open() call is flagged.
    with_opens: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for item in node.items:
                for sub in ast.walk(item.context_expr):
                    if _is_open_call(sub):
                        with_opens.add(id(sub))
    for node in ast.walk(tree):
        if _is_open_call(node) and id(node) not in with_opens:
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "IDM101",
                    "open() outside a 'with' statement — the file handle is never closed explicitly.",
                    "Use 'with open(...) as f:' so the file closes even when an error is raised.",
                )
            )

    # IDM102 / IDM103 / IDM105 — comparison rules; IDM104 — % formatting.
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for op, comparator in zip(node.ops, node.comparators):
                # IDM102 — type(x) compared with == / != / is / is not.
                if isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
                    type_side = None
                    if (
                        isinstance(node.left, ast.Call)
                        and isinstance(node.left.func, ast.Name)
                        and node.left.func.id == "type"
                        and len(node.left.args) == 1
                    ):
                        type_side = node.left
                    elif (
                        isinstance(comparator, ast.Call)
                        and isinstance(comparator.func, ast.Name)
                        and comparator.func.id == "type"
                        and len(comparator.args) == 1
                    ):
                        type_side = comparator
                    if type_side is not None:
                        verb = (
                            "=="
                            if isinstance(op, ast.Eq)
                            else "!=" if isinstance(op, ast.NotEq) else "is" if isinstance(op, ast.Is) else "is not"
                        )
                        findings.append(
                            Finding(
                                changed.path,
                                _real(getattr(node, "lineno", 0)),
                                "warning",
                                "IDM102",
                                f"type(x) compared with '{verb}' — exact-type checks miss subclasses.",
                                "Use 'isinstance(x, T)' instead.",
                            )
                        )
                        break
                # IDM103 — len(x) compared with 0.
                len_side = None
                zero_side = False
                if _is_len_call(node.left) and _is_zero(comparator):
                    len_side, zero_side = node.left, True
                elif _is_len_call(comparator) and _is_zero(node.left):
                    len_side, zero_side = comparator, True
                if len_side is not None and zero_side:
                    if isinstance(op, ast.Eq):
                        hint = "Use 'not x' instead."
                    elif isinstance(op, ast.NotEq):
                        hint = "Use 'x' instead."
                    elif isinstance(op, ast.Gt) and len_side is node.left:
                        hint = "Use 'x' instead."
                    elif isinstance(op, ast.Lt) and len_side is comparator:
                        hint = "Use 'x' instead."
                    else:
                        continue
                    verb = (
                        "=="
                        if isinstance(op, ast.Eq)
                        else "!="
                        if isinstance(op, ast.NotEq)
                        else ">"
                        if isinstance(op, ast.Gt)
                        else "<"
                    )
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "info",
                            "IDM103",
                            f"len(x) compared with 0 using '{verb}' — compare truthiness instead.",
                            hint,
                        )
                    )
                    break
                # IDM105 — x in d.keys() / x not in d.keys().
                if isinstance(op, (ast.In, ast.NotIn)) and isinstance(
                    comparator, ast.Call
                ):
                    func = comparator.func
                    if (
                        isinstance(func, ast.Attribute)
                        and func.attr == "keys"
                        and not comparator.args
                        and not comparator.keywords
                    ):
                        verb = "in" if isinstance(op, ast.In) else "not in"
                        findings.append(
                            Finding(
                                changed.path,
                                _real(getattr(node, "lineno", 0)),
                                "info",
                                "IDM105",
                                f"'{verb}' against d.keys() — membership in a dict already tests its keys.",
                                "Write 'x in d:' instead.",
                            )
                        )
                        break
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            # IDM104 — "%s" % value (old-style string formatting).
            if isinstance(node.left, ast.Constant) and isinstance(
                node.left.value, str
            ):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "info",
                        "IDM104",
                        "Old-style '%' string formatting — prefer an f-string or str.format().",
                        "Write f\"...{value}...\" or \"...\".format(value) instead.",
                    )
                )

    return findings


def _check_logging(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python logging rules LOG101–LOG105 (AST-based).

    LOG101 (warning): a logging call whose message is ``%``-formatted
    eagerly — ``logging.info("... %s" % value)`` builds the string
    even when the log level is disabled; pass the values as arguments
    instead (``logging.info("... %s", value)``). LOG102 (warning): a
    logging call whose message is an f-string — the same
    eager-formatting problem; pass the template and the values as
    arguments. LOG103 (warning): ``logging.exception(...)`` outside an
    ``except`` handler — there is no active exception to log, so the
    traceback is empty; use ``logging.error(...)`` instead, or move
    the call into a handler. LOG104 (info): a logging call whose
    message is built with ``str.format(...)`` — again eager
    formatting; pass the template and the values as arguments.
    LOG105 (info): ``logging.warn(...)`` is deprecated — use
    ``logging.warning(...)`` instead. Best-effort limits: only calls
    of the form ``<name>.<level>(...)`` are recognised, where
    ``<name>`` is a bare name such as ``logging`` or ``logger`` (a
    chained ``logging.getLogger(__name__).info(...)`` call is not);
    LOG103 treats a function defined inside an ``except`` handler as
    outside it, since the handler has finished by the time the
    function runs.
    """
    findings: list[Finding] = []

    _LEVELS = (
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "critical",
        "exception",
        "fatal",
    )

    def _is_logging_call(node: ast.AST) -> tuple[str, ast.expr | None] | None:
        """Return (level, first_arg) for a <name>.<level>(...) call."""
        if not isinstance(node, ast.Call):
            return None
        func = node.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr in _LEVELS
            and isinstance(func.value, ast.Name)
        ):
            return None
        first = node.args[0] if node.args else None
        return (func.attr, first)

    def _is_str_literal(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    def _visit(node: ast.AST, in_except: bool) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            # A nested function runs after its enclosing handler has
            # finished, so exception context does not carry into it.
            in_except = False
        if isinstance(node, ast.ExceptHandler):
            for child in ast.iter_child_nodes(node):
                _visit(child, True)
            return
        call = _is_logging_call(node)
        if call is not None:
            level, first = call
            lineno = _real(getattr(node, "lineno", 0))
            if level == "warn":
                findings.append(
                    Finding(
                        changed.path,
                        lineno,
                        "info",
                        "LOG105",
                        "logging.warn() is deprecated — use logging.warning() instead.",
                        "Rename the call to 'warning'; the behaviour is identical.",
                    )
                )
            elif level == "exception" and not in_except:
                findings.append(
                    Finding(
                        changed.path,
                        lineno,
                        "warning",
                        "LOG103",
                        "logging.exception() outside an 'except' handler — there is no active exception to log.",
                        "Use logging.error(...) here, or move the call inside an 'except' handler.",
                    )
                )
            if first is not None:
                if (
                    isinstance(first, ast.BinOp)
                    and isinstance(first.op, ast.Mod)
                    and _is_str_literal(first.left)
                ):
                    findings.append(
                        Finding(
                            changed.path,
                            lineno,
                            "warning",
                            "LOG101",
                            "Logging call formats its message with '%' eagerly — the string is built even when the level is disabled.",
                            "Pass the values as arguments: logging.info('... %s', value).",
                        )
                    )
                elif isinstance(first, ast.JoinedStr):
                    findings.append(
                        Finding(
                            changed.path,
                            lineno,
                            "warning",
                            "LOG102",
                            "Logging call passes an f-string — the message is formatted eagerly even when the level is disabled.",
                            "Pass the template and the values as arguments: logging.info('... %s', value).",
                        )
                    )
                elif (
                    isinstance(first, ast.Call)
                    and isinstance(first.func, ast.Attribute)
                    and first.func.attr == "format"
                    and _is_str_literal(first.func.value)
                ):
                    findings.append(
                        Finding(
                            changed.path,
                            lineno,
                            "info",
                            "LOG104",
                            "Logging call builds its message with str.format() eagerly — the string is built even when the level is disabled.",
                            "Pass the values as arguments: logging.info('... {}', value).",
                        )
                    )
        for child in ast.iter_child_nodes(node):
            _visit(child, in_except)

    _visit(tree, False)
    return findings


def _check_classes(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python class-design rules CLS101–CLS105 (AST-based).

    CLS101 (info): a class that defines attributes but no methods —
    a data-only container; a ``@dataclass`` or ``NamedTuple`` says
    the same thing with less boilerplate. CLS102 (info): an
    ``__init__`` whose whole body is a single ``super().__init__(...)``
    call passing the same arguments through — the method adds
    nothing and can be deleted. CLS103 (info): an instance method
    that never uses ``self`` — it does not need an instance, so it
    should be a ``@staticmethod`` (or a plain function). CLS104
    (warning): a class that defines ``__eq__`` without ``__hash__``
    (or the other way round) — defining ``__eq__`` sets
    ``__hash__`` to ``None``, so instances become unhashable.
    CLS105 (info): a class whose body is only a docstring and/or
    ``pass`` — an empty placeholder left behind. Best-effort
    limits: CLS103 counts a zero-argument ``super()`` call as using
    ``self``, since it only works inside a method; stub methods
    (only a docstring and/or ``pass``), dunder methods and methods
    decorated with ``@staticmethod``, ``@classmethod``,
    ``@property`` or ``@abstractmethod`` are exempt from CLS103;
    CLS102 only fires when every argument passed to ``super()`` is
    one of the ``__init__`` parameters (or there are no extra
    parameters and no arguments), and it skips ``*args`` /
    ``**kwargs`` forwarding.
    """
    findings: list[Finding] = []

    def _is_docstring_or_pass(stmt: ast.stmt) -> bool:
        if isinstance(stmt, ast.Pass):
            return True
        return (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        )

    def _decorator_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        names: set[str] = set()
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                names.add(dec.id)
            elif isinstance(dec, ast.Attribute):
                names.add(dec.attr)
        return names

    def _uses_self(method: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for node in ast.walk(method):
            if isinstance(node, ast.Name) and node.id == "self":
                return True
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "super"
                and not node.args
                and not node.keywords
            ):
                # Zero-argument super() only works inside a method,
                # so it counts as using self.
                return True
        return False

    def _is_redundant_init(
        method: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        if method.name != "__init__":
            return False
        body = method.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            # A leading docstring is not a real statement.
            body = body[1:]
        if len(body) != 1:
            return False
        stmt = body[0]
        if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
            return False
        call = stmt.value
        func = call.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "__init__"
            and isinstance(func.value, ast.Call)
            and isinstance(func.value.func, ast.Name)
            and func.value.func.id == "super"
        ):
            return False
        if method.args.vararg is not None or method.args.kwarg is not None:
            return False
        if any(kw.arg is None for kw in call.keywords):
            return False
        params = [a.arg for a in method.args.args[1:]]
        params += [a.arg for a in method.args.kwonlyargs]
        passed: list[str] = []
        for arg in call.args:
            if isinstance(arg, ast.Starred) or not isinstance(arg, ast.Name):
                return False
            passed.append(arg.id)
        for kw in call.keywords:
            if not isinstance(kw.value, ast.Name):
                return False
            passed.append(kw.value.id)
        return sorted(passed) == sorted(params)

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        methods = [
            stmt
            for stmt in node.body
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        attrs = [
            stmt
            for stmt in node.body
            if isinstance(stmt, (ast.Assign, ast.AnnAssign))
        ]
        class_line = _real(getattr(node, "lineno", 0))
        if not methods and attrs:
            findings.append(
                Finding(
                    changed.path,
                    class_line,
                    "info",
                    "CLS101",
                    f"Class '{node.name}' defines attributes but no methods — it is only a data container.",
                    "Use a @dataclass or a NamedTuple instead; they give you __init__ and __eq__ for free.",
                )
            )
        elif not methods and all(_is_docstring_or_pass(s) for s in node.body):
            findings.append(
                Finding(
                    changed.path,
                    class_line,
                    "info",
                    "CLS105",
                    f"Class '{node.name}' is empty — its body is only a docstring and/or 'pass'.",
                    "Delete it if it is a leftover placeholder, or fill in the behaviour it is meant to hold.",
                )
            )
        method_names = {method.name for method in methods}
        if ("__eq__" in method_names) != ("__hash__" in method_names):
            if "__eq__" in method_names:
                message = (
                    f"Class '{node.name}' defines __eq__ but not __hash__ — "
                    "defining __eq__ sets __hash__ to None, so instances become unhashable."
                )
            else:
                message = (
                    f"Class '{node.name}' defines __hash__ but not __eq__ — "
                    "hashing and equality will disagree."
                )
            findings.append(
                Finding(
                    changed.path,
                    class_line,
                    "warning",
                    "CLS104",
                    message,
                    "Define __eq__ and __hash__ together, or neither.",
                )
            )
        for method in methods:
            start = _real(getattr(method, "lineno", 0))
            if _is_redundant_init(method):
                findings.append(
                    Finding(
                        changed.path,
                        start,
                        "info",
                        "CLS102",
                        f"__init__ in '{node.name}' only calls super().__init__() with the same arguments — it adds nothing.",
                        "Delete the method; the parent's __init__ runs anyway.",
                    )
                )
            if (
                method.args.args
                and method.args.args[0].arg == "self"
                and not method.name.startswith("__")
                and not _decorator_names(method)
                & {"staticmethod", "classmethod", "property", "abstractmethod"}
                and not all(_is_docstring_or_pass(s) for s in method.body)
                and not _uses_self(method)
            ):
                findings.append(
                    Finding(
                        changed.path,
                        start,
                        "info",
                        "CLS103",
                        f"Method '{method.name}' never uses 'self' — it does not need an instance.",
                        "Make it a @staticmethod, or move it out of the class as a plain function.",
                    )
                )
    return findings


def _check_functions(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python function-design rules FN101–FN105 (AST-based).

    FN101 (warning): a function that returns a value on some paths
    but falls off the end or returns bare on others — callers get
    ``None`` on the paths that do not return a value. FN102 (info):
    a parameter that is never read in the function body. FN103
    (warning): a ``return`` with a value inside a generator function
    — the value is silently discarded (it only becomes
    ``StopIteration.value``). FN104 (info): a function defined inside
    another function and never referenced there. FN105 (warning): a
    default argument that is a function call — it is evaluated once,
    when the ``def`` statement runs, so every call shares the same
    object. Best-effort limits: FN101 treats a trailing ``if`` /
    ``else`` whose branches both return as returning, but a trailing
    loop or ``try`` is treated as falling off the end; FN102 counts a
    parameter as used if its name is loaded anywhere in the function,
    including inside a nested function (a closure) or in a nested
    function's default value or decorator, and a nested function
    parameter with the same name can mask a genuinely unused outer
    parameter; FN102 skips ``self`` / ``cls``, ``*args`` /
    ``**kwargs``, and stub, ``@overload`` or ``@abstractmethod``
    functions; FN105 flags every call default, including harmless
    ones such as a constant computed once.
    """
    findings: list[Finding] = []

    def _is_stub(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            # A leading docstring is not a real statement.
            body = body[1:]
        if not body:
            return True
        if all(
            isinstance(stmt, ast.Pass)
            or (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and stmt.value.value is Ellipsis
            )
            for stmt in body
        ):
            return True
        return len(body) == 1 and isinstance(body[0], ast.Raise)

    def _decorator_names(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        names: set[str] = set()
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                names.add(dec.id)
            elif isinstance(dec, ast.Attribute):
                names.add(dec.attr)
        return names

    def _nodes_without_nested(root: ast.AST) -> list[ast.AST]:
        """All nodes under ``root`` except inside nested functions.

        A nested function's own body is skipped (its returns and
        yields belong to it, not to the enclosing function), but a
        lambda body is kept: it has no ``return`` statements and a
        parameter loaded inside it is still a use of the outer one.
        """
        collected: list[ast.AST] = []
        stack: list[ast.AST] = [root]
        while stack:
            node = stack.pop()
            if (
                node is not root
                and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                continue
            collected.append(node)
            stack.extend(ast.iter_child_nodes(node))
        return collected

    def _block_always_returns(stmts: list[ast.stmt]) -> bool:
        if not stmts:
            return False
        last = stmts[-1]
        if isinstance(last, (ast.Return, ast.Raise)):
            return True
        if isinstance(last, ast.If) and last.orelse:
            return _block_always_returns(last.body) and _block_always_returns(
                last.orelse
            )
        return False

    def _nested_defs(
        func: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """Function definitions inside ``func``, at any depth.

        Nested definitions are collected but never descended into,
        so a function defined inside a nested function belongs to
        that nested function, not to ``func``.
        """
        found: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

        def visit(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found.append(child)
                elif isinstance(child, ast.stmt):
                    visit(child)

        visit(func)
        return found

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        start = _real(getattr(node, "lineno", 0))
        own_nodes = _nodes_without_nested(node)
        returns = [n for n in own_nodes if isinstance(n, ast.Return)]
        value_returns = [r for r in returns if r.value is not None]
        bare_returns = [r for r in returns if r.value is None]
        if (
            not _is_stub(node)
            and value_returns
            and (bare_returns or not _block_always_returns(node.body))
        ):
            findings.append(
                Finding(
                    changed.path,
                    start,
                    "warning",
                    "FN101",
                    f"Function '{node.name}' returns a value on some paths but falls off the end or returns bare on others — callers get None on those paths.",
                    "Return an explicit value on every path, or return None deliberately and annotate the function accordingly.",
                )
            )
        yields = [
            n
            for n in own_nodes
            if isinstance(n, (ast.Yield, ast.YieldFrom))
        ]
        if yields:
            for ret in value_returns:
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(ret, "lineno", 0)),
                        "warning",
                        "FN103",
                        f"Return with a value inside generator '{node.name}' — the value is silently discarded.",
                        "Yield the value instead, or collect the results and return them from a regular function.",
                    )
                )
        if _is_stub(node) or _decorator_names(node) & {
            "overload",
            "abstractmethod",
        }:
            continue
        used: set[str] = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                used.add(n.id)
            elif isinstance(n, ast.AugAssign) and isinstance(
                n.target, ast.Name
            ):
                # `x += 1` reads x, even though the target is Store.
                used.add(n.target.id)
        params = (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
        if params and params[0].arg in ("self", "cls"):
            params = params[1:]
        for param in params:
            if param.arg not in used:
                findings.append(
                    Finding(
                        changed.path,
                        start,
                        "info",
                        "FN102",
                        f"Parameter '{param.arg}' in '{node.name}' is never used.",
                        "Remove it, or use it — an unused parameter misleads callers about what the function needs.",
                    )
                )
        for nested in _nested_defs(node):
            if nested.name not in used:
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(nested, "lineno", 0)),
                        "info",
                        "FN104",
                        f"Nested function '{nested.name}' is defined but never used inside '{node.name}'.",
                        "Delete it, or call it where it was meant to run.",
                    )
                )
        positional = list(node.args.posonlyargs) + list(node.args.args)
        defaults = node.args.defaults
        for arg, default in zip(
            positional[len(positional) - len(defaults):] if defaults else [],
            defaults,
        ):
            if isinstance(default, ast.Call):
                findings.append(
                    Finding(
                        changed.path,
                        start,
                        "warning",
                        "FN105",
                        f"Default argument '{arg.arg}' in '{node.name}' is a function call — it is evaluated once, when the function is defined.",
                        "Use None as the default and call the function inside the body, so every call gets a fresh value.",
                    )
                )
        for arg, default in zip(
            node.args.kwonlyargs, node.args.kw_defaults
        ):
            if default is not None and isinstance(default, ast.Call):
                findings.append(
                    Finding(
                        changed.path,
                        start,
                        "warning",
                        "FN105",
                        f"Default argument '{arg.arg}' in '{node.name}' is a function call — it is evaluated once, when the function is defined.",
                        "Use None as the default and call the function inside the body, so every call gets a fresh value.",
                    )
                )
    return findings


def _check_strings(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python string rules STR101–STR105 (AST-based).

    STR101 (info): an f-string with no interpolated values —
    ``f"ready"`` is just a plain string with a needless ``f`` prefix;
    drop the prefix. STR102 (warning): a pure string method called
    as a bare statement, such as ``name.strip()`` — strings are
    immutable, so the new string is built and immediately thrown
    away; assign or return the result. STR103 (info): ``str()``
    called on a string literal — the value is already a string;
    use the literal directly. STR104 (info): two string literals
    joined with ``+`` — merge them into one literal (adjacent
    literals are concatenated by Python anyway). STR105 (warning):
    ``.join()`` called on a single string literal, such as
    ``",".join("abc")`` — join iterates the string character by
    character, producing ``"a,b,c"``, which is almost certainly not
    what was meant; pass a list of strings instead. Best-effort
    limits: STR102 recognises the method name only, since the
    receiver's type cannot be known from a diff fragment, so a
    same-named method on another object that mutates in place would
    be flagged wrongly; STR105 only flags a literal argument, not a
    variable that happens to hold a string.
    """
    findings: list[Finding] = []

    _PURE_STRING_METHODS = frozenset({
        "capitalize", "casefold", "center", "expandtabs", "format",
        "format_map", "join", "ljust", "lower", "lstrip",
        "removeprefix", "removesuffix", "replace", "rjust", "rstrip",
        "strip", "swapcase", "title", "upper", "zfill",
    })

    def _is_str_literal(node: ast.AST) -> bool:
        return isinstance(node, ast.Constant) and isinstance(node.value, str)

    for node in ast.walk(tree):
        # STR101 — f-string with no placeholders.
        if isinstance(node, ast.JoinedStr):
            if not any(
                isinstance(part, ast.FormattedValue) for part in node.values
            ):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "info",
                        "STR101",
                        "f-string with no placeholders — the 'f' prefix does nothing.",
                        "Drop the 'f' prefix and use a plain string.",
                    )
                )
        # STR102 — pure string method result discarded.
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            func = node.value.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _PURE_STRING_METHODS
            ):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "warning",
                        "STR102",
                        f"Result of '.{func.attr}()' is discarded — strings are immutable, so the original is unchanged.",
                        "Assign or return the result, e.g. 'name = name.strip()'.",
                    )
                )
        # STR103 — str() on a string literal.
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "str"
            and len(node.args) == 1
            and not node.keywords
            and _is_str_literal(node.args[0])
        ):
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "info",
                    "STR103",
                    "str() called on a string literal — the value is already a string.",
                    "Use the string literal directly.",
                )
            )
        # STR104 — two string literals joined with +.
        elif (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Add)
            and _is_str_literal(node.left)
            and _is_str_literal(node.right)
        ):
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "info",
                    "STR104",
                    "Two string literals joined with '+' — merge them into one literal.",
                    "Write a single string literal, or place the literals side by side.",
                )
            )
        # STR105 — .join() on a single string literal.
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and len(node.args) == 1
            and _is_str_literal(node.args[0])
        ):
            findings.append(
                Finding(
                    changed.path,
                    _real(getattr(node, "lineno", 0)),
                    "warning",
                    "STR105",
                    "'.join()' called on a single string — it will join the string character by character.",
                    "Pass a list of strings instead, e.g. ','.join(['a', 'b', 'c']).",
                )
            )
    return findings


def _check_returns(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python return-value rules RET101–RET105 (AST-based).

    RET101 (warning): the result of ``.sort()`` or ``.reverse()``
    used as a value — both sort/reverse the list in place and
    return ``None``, so ``x = items.sort()`` sets ``x`` to ``None``;
    call it on its own line and use the list itself (or ``sorted()``
    for a new list). RET102 (warning): the result of an in-place
    list mutator (``.append()``, ``.extend()``, ``.insert()``,
    ``.remove()``, ``.clear()``) used as a value — they modify the
    list and return ``None``. RET103 (warning): the result of
    ``.update()`` used as a value — it merges in place and returns
    ``None``. RET104 (warning): the result of ``.shuffle()`` used
    as a value — it shuffles in place and returns ``None``.
    RET105 (warning): the result of a set mutator (``.add()``,
    ``.discard()``) used as a value — they modify the set in place
    and return ``None``. "Used as a value" means the call appears
    anywhere except as a bare statement: assigned, returned, nested
    in another expression, and so on. Best-effort limits: the rules
    recognise the method name only, since the receiver's type
    cannot be known from a diff fragment, so a same-named method on
    another object that does return a value would be flagged
    wrongly; RET104 only recognises the attribute form
    (``random.shuffle(...)``), not a bare ``shuffle(...)`` imported
    with ``from random import shuffle``.
    """
    findings: list[Finding] = []

    _NONE_RETURNING = {
        "sort": (
            "RET101",
            "sorts in place and returns None",
            "Call '.sort()' on its own line, then use the list itself — or use sorted() for a new list.",
        ),
        "reverse": (
            "RET101",
            "reverses in place and returns None",
            "Call '.reverse()' on its own line, then use the list itself — or use reversed() for an iterator.",
        ),
        "append": (
            "RET102",
            "modifies the list in place and returns None",
            "Call it on its own line, then use the list itself.",
        ),
        "extend": (
            "RET102",
            "modifies the list in place and returns None",
            "Call it on its own line, then use the list itself.",
        ),
        "insert": (
            "RET102",
            "modifies the list in place and returns None",
            "Call it on its own line, then use the list itself.",
        ),
        "remove": (
            "RET102",
            "modifies the collection in place and returns None",
            "Call it on its own line, then use the collection itself.",
        ),
        "clear": (
            "RET102",
            "modifies the collection in place and returns None",
            "Call it on its own line, then use the collection itself.",
        ),
        "update": (
            "RET103",
            "merges in place and returns None",
            "Call '.update()' on its own line, then use the updated object itself.",
        ),
        "shuffle": (
            "RET104",
            "shuffles in place and returns None",
            "Call '.shuffle()' on its own line, then use the list itself.",
        ),
        "add": (
            "RET105",
            "modifies the set in place and returns None",
            "Call it on its own line, then use the set itself.",
        ),
        "discard": (
            "RET105",
            "modifies the set in place and returns None",
            "Call it on its own line, then use the set itself.",
        ),
    }

    # Calls that stand alone as a bare statement use their result
    # correctly (the in-place change is the point), so they are exempt.
    bare_calls = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
    }

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        entry = _NONE_RETURNING.get(func.attr)
        if entry is None or id(node) in bare_calls:
            continue
        rule, effect, suggestion = entry
        findings.append(
            Finding(
                changed.path,
                _real(getattr(node, "lineno", 0)),
                "warning",
                rule,
                f"Result of '.{func.attr}()' is used as a value — it {effect}.",
                suggestion,
            )
        )
    return findings


def _check_dicts(
    tree: ast.AST, changed: ChangedFile, _real
) -> list[Finding]:
    """Python dictionary rules DCT101–DCT105 (AST-based).

    DCT101 (warning): ``d[key] if key in d else default`` — the
    conditional expression looks the key up twice; ``d.get(key,
    default)`` does it in one call (the mirrored ``default if key
    not in d else d[key]`` form is flagged too). DCT102 (warning):
    the same lookup written as an ``if`` / ``else`` that assigns
    ``d[key]`` on one branch and a default on the other — again,
    ``d.get(key, default)`` says it in one line. DCT103 (warning):
    ``if key not in d: d[key] = default`` — ``d.setdefault(key,
    default)`` inserts the default only when the key is missing and
    returns the value either way. DCT104 (info): ``dict()`` with no
    arguments — the empty-dict literal ``{}`` is shorter and
    clearer. DCT105 (warning): ``d[key] = d[key] + 1`` — the
    augmented form ``d[key] += 1`` states the update directly (for
    counting, ``collections.Counter`` may fit even better).
    Best-effort limits: the dict and key are matched by name /
    expression shape only, since their types cannot be known from a
    diff fragment, so a same-shaped pattern on another mapping type
    would be flagged too; DCT102 only recognises a single assignment
    on each branch, and DCT105 only when the right-hand side is a
    binary operation on the very same subscript.
    """
    findings: list[Finding] = []

    def _same_expr(left: ast.expr, right: ast.expr) -> bool:
        # Compare by source shape: ast.dump would also compare the
        # Load/Store context, so `d[key]` as a target would never
        # match `d[key]` as a value.
        return ast.unparse(left) == ast.unparse(right)

    def _subscript_of(expr: ast.expr, container: ast.expr, key: ast.expr) -> bool:
        return (
            isinstance(expr, ast.Subscript)
            and _same_expr(expr.value, container)
            and _same_expr(expr.slice, key)
        )

    def _membership(test: ast.expr) -> tuple[ast.expr, ast.expr, bool] | None:
        """Return (key, container, negated) for `key in d` / `key not in d`."""
        if not isinstance(test, ast.Compare):
            return None
        if len(test.ops) != 1 or len(test.comparators) != 1:
            return None
        op = test.ops[0]
        if isinstance(op, ast.In):
            return test.left, test.comparators[0], False
        if isinstance(op, ast.NotIn):
            return test.left, test.comparators[0], True
        return None

    def _single_assign(body: list[ast.stmt]) -> ast.Assign | None:
        if len(body) != 1 or not isinstance(body[0], ast.Assign):
            return None
        if len(body[0].targets) != 1:
            return None
        return body[0]

    for node in ast.walk(tree):
        # DCT101 — d[key] if key in d else default (and the mirror form).
        if isinstance(node, ast.IfExp):
            membership = _membership(node.test)
            if membership is not None:
                key, container, negated = membership
                lookup = node.orelse if negated else node.body
                if _subscript_of(lookup, container, key):
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "DCT101",
                            "Conditional expression looks the key up twice — 'd[key] if key in d else default'.",
                            "Use d.get(key, default) — one lookup, same result.",
                        )
                    )

        # DCT102 / DCT103 — if/else forms of the same patterns.
        if isinstance(node, ast.If):
            membership = _membership(node.test)
            if membership is not None:
                key, container, negated = membership
                body_assign = _single_assign(node.body)
                else_assign = _single_assign(node.orelse)
                if body_assign is not None and else_assign is not None:
                    lookup_assign = else_assign if negated else body_assign
                    default_assign = body_assign if negated else else_assign
                    same_target = _same_expr(
                        lookup_assign.targets[0], default_assign.targets[0]
                    )
                    if same_target and _subscript_of(
                        lookup_assign.value, container, key
                    ):
                        findings.append(
                            Finding(
                                changed.path,
                                _real(getattr(node, "lineno", 0)),
                                "warning",
                                "DCT102",
                                "If/else assigns d[key] on one branch and a default on the other.",
                                "Use d.get(key, default) — one lookup, same result.",
                            )
                        )
                if negated and body_assign is not None and not node.orelse:
                    target = body_assign.targets[0]
                    if _subscript_of(target, container, key):
                        findings.append(
                            Finding(
                                changed.path,
                                _real(getattr(node, "lineno", 0)),
                                "warning",
                                "DCT103",
                                "'if key not in d: d[key] = default' — inserting a default by hand.",
                                "Use d.setdefault(key, default) — it inserts only when missing and returns the value.",
                            )
                        )

        # DCT104 — dict() with no arguments.
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "dict"
                and not node.args
                and not node.keywords
            ):
                findings.append(
                    Finding(
                        changed.path,
                        _real(getattr(node, "lineno", 0)),
                        "info",
                        "DCT104",
                        "dict() with no arguments — an empty dict in longhand.",
                        "Use the literal {} instead.",
                    )
                )

        # DCT105 — d[key] = d[key] <op> ...
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            value = node.value
            if (
                isinstance(target, ast.Subscript)
                and isinstance(value, ast.BinOp)
                and _same_expr(value.left, target)
            ):
                op_name = type(value.op).__name__
                symbol = {
                    "Add": "+=",
                    "Sub": "-=",
                    "Mult": "*=",
                    "Div": "/=",
                    "FloorDiv": "//=",
                    "Mod": "%=",
                    "Pow": "**=",
                    "BitOr": "|=",
                    "BitAnd": "&=",
                    "BitXor": "^=",
                    "LShift": "<<=",
                    "RShift": ">>=",
                }.get(op_name)
                if symbol is not None:
                    findings.append(
                        Finding(
                            changed.path,
                            _real(getattr(node, "lineno", 0)),
                            "warning",
                            "DCT105",
                            "Assigning d[key] from an expression on d[key] itself.",
                            f"Use the augmented form 'd[key] {symbol} ...' — for counting, collections.Counter may fit even better.",
                        )
                    )

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
    findings.extend(_check_async(tree, changed, _real))
    findings.extend(_check_idioms(tree, changed, _real))
    findings.extend(_check_logging(tree, changed, _real))
    findings.extend(_check_classes(tree, changed, _real))
    findings.extend(_check_functions(tree, changed, _real))
    findings.extend(_check_strings(tree, changed, _real))
    findings.extend(_check_returns(tree, changed, _real))
    findings.extend(_check_dicts(tree, changed, _real))
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
