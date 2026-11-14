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
