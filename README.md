# ai-pr-reviewer-action

Free, open-source GitHub Action that reviews PR diffs for **security issues,
bug patterns, complexity, imports, error handling, style and missing tests** — static analysis first, with an
optional AI summary when you bring your own Groq key (BYOK). No paid service,
no data stored anywhere.

## What it checks

| Category | Examples |
| --- | --- |
| Security | Hardcoded credentials, `eval()` / `exec()`, shell injection (`shell=True`, `os.system`), unsafe `pickle` / `yaml.load`, weak hashes, disabled TLS verification; string commands to `subprocess`, `os.popen()`, `random` for tokens, `assert` outside tests, `tempfile.mktemp()`, world-writable `os.chmod()` (Python AST: SEC101–SEC105) |
| Bugs | Bare `except:`, silent `except Exception:`, mutable default arguments, `TODO` / `FIXME` markers, string-built queries; unreachable code after `return` / `raise` / `break` / `continue`, duplicate dict keys, `is` with a literal, constant `if` / `while` conditions, comparing a variable to itself (Python AST: BUG101–BUG105) |
| Performance | String concatenation with `+=` inside a loop, `range(len(x))`, membership tests against a list literal, loops that only append to a list, iterating `d.keys()` (Python AST: PERF101–PERF105) |
| Documentation | Public functions and classes without a docstring, empty docstrings, summary lines without a full stop, TODO / FIXME markers inside a docstring (Python AST: DOC101–DOC105) |
| Type hints | Public functions without a return annotation, unannotated parameters, bare `Any`, deprecated `typing.List` / `Dict` / `Set` / `Tuple` / `FrozenSet` / `Type` generics, functions annotated `-> None` that return a value (Python AST: TYP101–TYP105) |
| Async / concurrency | `time.sleep()` inside an `async def`, async functions called without `await`, `async def` functions that never await, `run_until_complete()` inside an `async def`, bare `asyncio.create_task()` statements that discard the task (Python AST: ASC101–ASC105) |
| Idioms | `open()` outside a `with` statement, `type(x) == T` instead of `isinstance`, `len(x) == 0` instead of truthiness, old-style `%` string formatting, `x in d.keys()` instead of `x in d` (Python AST: IDM101–IDM105) |
| Logging | Logging calls that format the message eagerly (`%`, f-strings, `str.format()`), `logging.exception()` outside an `except` handler, deprecated `logging.warn()` (Python AST: LOG101–LOG105) |
| Class design | Classes with attributes but no methods, `__init__` that only calls `super().__init__()` with the same arguments, methods that never use `self`, `__eq__` without `__hash__`, empty classes (Python AST: CLS101–CLS105) |
| Function design | Functions that return a value on some paths but fall off the end or return bare on others, parameters that are never used, return values inside generators, nested functions that are never called, default arguments that are function calls (Python AST: FN101–FN105) |
| Strings | f-strings with no placeholders, pure string methods whose result is discarded, `str()` on a string literal, two string literals joined with `+`, `.join()` on a single string (Python AST: STR101–STR105) |
| Return values | Results of in-place methods that return `None` used as values — `.sort()` / `.reverse()`, `.append()` / `.extend()` / `.insert()` / `.remove()` / `.clear()`, `.update()`, `.shuffle()`, `.add()` / `.discard()` (Python AST: RET101–RET105) |
| Dictionaries | Hand-rolled lookups that `.get()` / `.setdefault()` say in one call — `d[key] if key in d else default`, the same lookup as an `if` / `else`, `if key not in d: d[key] = default`, `dict()` with no arguments, `d[key] = d[key] + 1` instead of `+=` (Python AST: DCT101–DCT105) |
| Error handling | Silent `except` handlers (body is only `pass`), raising a new exception inside a handler without `from`, catching `BaseException`, a `try` block that does nothing (Python AST: ERR001–ERR004) |
| Complexity | Functions over 50 lines, over 5 arguments, nesting deeper than 3 levels, more than 5 returns, boolean flag parameters, nested or over-long comprehensions, lambdas assigned to a variable (Python AST: CPL001–CPL007; JS/TS via brace tracking) |
| Imports | Wildcard imports, unused imports, imports inside a function or class instead of at the top of the module (Python AST: IMP001–IMP003) |
| JavaScript / TypeScript | Leftover `console.log`, `debugger`, `var`, loose `==` / `!=`, `document.write`, `innerHTML` assignment, `parseInt` without a radix, blocking dialogs, `new Function()`, `: any` types, `eval()`, string timers, `with` statement, direct `document.cookie` access, comparator-less `.sort()`, long functions, too many parameters, deep nesting (JS011–JS018) |
| Tests | Source files changed with no test file touched in the PR |
| Style | Lines over 120 characters, leftover `print()` calls, trailing whitespace, multiple statements on one line, `==` comparisons to `None`/`True`/`False`, tab indentation (Python AST: STY003–STY006) |

Checks run on **added lines only** — it never nags about pre-existing code.
Every finding carries a stable rule id (`SEC001`, `BUG005`, `CPL001`, …),
a severity and a fix suggestion.

## Usage

```yaml
name: PR review
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: taha080/ai-pr-reviewer-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on: error        # error | warning | none
```

The action posts **one comment per PR** and updates it on every push, so your
PR thread stays clean. `fail-on: error` (the default) fails the check when a
blocking finding exists; use `warning` to also fail on warnings, or `none`
to report without failing. If two workflows review the same PR (for example
this repo's dogfood workflow alongside the released action), give each a
different `comment-marker` so each keeps its own comment instead of
overwriting the other's:

```yaml
      - uses: taha080/ai-pr-reviewer-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          comment-marker: security-scan   # its own comment, updated in place
```

To silence rules you have deliberately decided not to enforce, pass their
ids to `ignore-rules` (comma-separated, case-insensitive):

```yaml
      - uses: taha080/ai-pr-reviewer-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          ignore-rules: STY002, BUG003   # allow print() and TODO markers
```

### Optional AI summary (BYOK Groq)

Add a `GROQ_API_KEY` repository secret and pass it in:

```yaml
      - uses: taha080/ai-pr-reviewer-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          groq-api-key: ${{ secrets.GROQ_API_KEY }}
```

The key is only sent to Groq for that run and is never stored or logged.
Without it the action still reviews fully on static analysis alone.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `github-token` | yes | `${{ github.token }}` | Token to read the diff and post the comment |
| `groq-api-key` | no | `""` | Optional Groq key for the AI summary |
| `fail-on` | no | `error` | `error`, `warning` or `none` |
| `max-findings` | no | `30` | Max findings included in the comment |
| `ignore-rules` | no | `""` | Comma-separated rule ids to skip, e.g. `STY002, BUG003` |
| `comment-marker` | no | `""` | Name for this run's comment; two workflows on one PR need different markers |
| `pr-number` | no | `""` | PR to review (defaults to the triggering PR) |

## Outputs

| Output | Description |
| --- | --- |
| `findings` | Total number of findings |
| `errors` | Number of error-severity findings |
| `verdict` | One-line verdict of the review |

## Local run

No dependencies — Python 3.9+ standard library only.

```bash
python3 -m unittest discover -s tests -v   # run the tests
python3 -m py_compile src/*.py              # compile check
```

To review a PR locally, set `GITHUB_TOKEN`, `GITHUB_REPOSITORY`
(`owner/repo`) and a `GITHUB_EVENT_PATH` JSON file containing
`{"pull_request": {"number": 1}}`, then run `python3 src/main.py`.

## How it works

```
PR diff (GitHub API) → src/diffparse.py → src/checks.py → src/report.py → PR comment
                                        ↘ optional Groq summary (BYOK)
```

- `src/diffparse.py` — parses unified diffs into added lines with real line numbers.
- `src/checks.py` — the rule engine (regex rules + Python AST checks + PR-level tests check).
- `src/checks_js.py` — the JavaScript / TypeScript rule set (JS001–JS018).
- `src/report.py` — renders the Markdown review comment.
- `src/main.py` — fetches the diff, runs the checks, posts/updates the comment.

The repo dogfoods itself: `.github/workflows/dogfood.yml` runs the action
from the PR's own checkout (`uses: ./`) on every pull request, and
`examples/bad-example.js` / `examples/bad-example.py` are fixtures with
deliberately flagged code so each rule change can be verified against a real
review comment.

## Status

Day 1 (6 Nov 2026): core action shipped — rule engine, report renderer,
entry point, tests (11 passing), CI workflow and this README.

Day 2 (7 Nov 2026): JS/TS rule set shipped (JS001–JS010, 7 new tests,
18 passing) and the action now dogfoods itself — `.github/workflows/dogfood.yml`
reviews this repo's own PRs with the local action, verified against real
PR #1 using the `examples/bad-example.js` fixture (dogfooding caught and
fixed a JS002 bug: `debugger` with a trailing comment was missed). Release
v1 published the same day.

Day 3 (8 Nov 2026): JS/TS complexity rules shipped (JS011–JS013, 11 new tests,
29 passing) — long functions, too many parameters and deep nesting, measured
with a brace-tracking scanner that ignores strings/comments and does not count
object literals as nesting. Dogfooded on real PR #2: the action's own review
comment flagged JS011/JS012/JS013 on the fixture (61-line, 6-parameter,
4-level function), and the PR was merged. Next: Dependabot triage on
aws-eks-devops-platform, or the next rule set.

Day 4 (9 Nov 2026): Dependabot triage on aws-eks-devops-platform — all 12 open
Dependabot PRs merged after CI-green + version-only checks (tls patch bumps,
Python deps incl. pytest 9.2.0 and sqlalchemy 2.1.8 after Dependabot rebases,
CI-action majors incl. checkout 7 and setup-python 7). JS/TS dangerous-API
rules shipped (JS014–JS018, 3 new tests, 32 passing): `eval()`, string timers,
the `with` statement, direct `document.cookie` access and comparator-less
`.sort()`. Dogfooded on real PR #3: the action's own review comment flagged
JS014–JS018 on the fixture (plus SEC002 on `eval()`), and the PR was merged.
Note: the "PR review example" check on that PR failed by design — the released
v1 action flags the deliberately-bad fixture's `eval()` as an error and
`fail-on: error` exits 1; the CI and dogfood checks that test the change were
green, so the merge went ahead on those.

Day 5 (10 Nov 2026): Python complexity/quality rules shipped (CPL004–CPL007,
6 new tests, 38 passing) — more than 5 returns, boolean flag parameters,
nested or over-long comprehensions, and lambdas assigned to a variable.
Returns inside nested functions are not counted, and a nested comprehension
is flagged once, on the outer one. Dogfooded on real PR #4: the action's own
review comment flagged CPL004/CPL005/CPL006/CPL007 on the new
`examples/bad-example.py` fixture (plus the expected TST001), and the PR was
merged with all 3 checks green. Next: a v1.1 release with JS001–JS018 and
CPL004–CPL007.

Day 6 (11 Nov 2026): `ignore-rules` input shipped (5 new tests, 43 passing)
— pass comma-separated rule ids (case-insensitive) to silence rules a repo
has deliberately decided not to enforce, e.g. `ignore-rules: STY002`. It is
wired through `review_files()`, `main.py` and `action.yml`, and applies to
every rule category including the PR-level TST001 check. Dogfooded on real
PR #5: the dogfood workflow passes `ignore-rules: STY002`, and the action's
own review comment flagged BUG003 on the new `examples/ignore-example.py`
fixture but NOT STY002, exactly as intended; the PR was merged. Release v1.1 published the same day.

Day 7 (12 Nov 2026): Python import rules shipped (IMP001–IMP003, 6 new tests,
49 passing) — wildcard imports, unused imports, and imports inside a function
or class instead of at the top of the module. IMP002 only flags a name that is
never used anywhere else in the added lines, and is skipped entirely when the
fragment defines `__all__` (re-exported names are used by definition).
Dogfooded on real PR #6: the dogfood run's review comment flagged
IMP001/IMP002/IMP003 on the new `examples/import-example.py` fixture (plus the
expected TST001), and the PR was merged with all 3 checks green. Next: a v1.2
release with IMP001–IMP003, or the next rule set.

Day 8 (13 Nov 2026): Python naming rules shipped (NAM001–NAM004, 8 new tests,
57 passing) — function names not in snake_case, class names not in
PascalCase, module-level constants not in UPPER_SNAKE_CASE, and names that
shadow a Python builtin (parameters, assignments, loop targets, and
function/class names; methods inside a class body are exempt from the
shadowing check since they do not hide the builtin in module scope, and
dunder methods are exempt from the snake_case check). NAM003 only fires on
a literal-valued module constant that already uses mixed case — plain
lowercase module variables are left alone. Dogfooded on real PR #7: the
action's own review comment flagged NAM001/NAM002/NAM003/NAM004 (twice) on
the new `examples/naming-example.py` fixture (plus the expected TST001), and
the PR was merged with all 3 checks green. Next: a v1.2 release with
IMP001–IMP003 and NAM001–NAM004, or the next rule set.

Day 9 (14 Nov 2026): Python style rules shipped (STY003–STY006, 7 new tests,
64 passing) — trailing whitespace, multiple statements on one line separated
by `;`, comparisons to `None`/`True`/`False` with `==`/`!=` instead of
`is`/`is not`, and tab indentation. STY004 and STY005 are AST checks (two
statements share a line number; a comparison node with a singleton operand),
while STY003 and STY006 are line checks that run on every file type.
Dogfooded on real PR #8: the action's own review comment flagged STY003,
STY004, STY005 (twice) and STY006 on the new `examples/style-example.py`
fixture (plus the expected TST001), and the PR was merged with all 3 checks
green. Next: a v1.2 release with IMP001–IMP003, NAM001–NAM004 and STY003–STY006,
or the next rule set. Release v1.2 published the same day.

Day 10 (15 Nov 2026): `comment-marker` input shipped (9 new tests,
73 passing) — give each workflow reviewing the same PR a different marker
name and each keeps its own review comment, keyed by a hidden HTML comment
(`<!-- ai-pr-reviewer:<name> -->`); names are sanitised (only letters,
digits, `-` and `_`, runs of `-` collapsed) and an empty name falls back
to the default marker. The repo's own dogfood workflow now uses
`comment-marker: dogfood`. Dogfooded on real PR #9: the dogfood run's
comment flagged TST001 + STY003 (and no STY002, which dogfood ignores),
while the released example run posted its own separate comment flagging
TST001 + STY002 — the two comments no longer overwrite each other, fixing
the clash seen on PRs #6–#8, where the later run kept overwriting the
shared comment. Note: the example run did not flag STY003 because the `v1`
tag still pointed at the Day 2 code (7 Nov) — the major tag was never moved
for v1.1 or v1.2. Release v1.3 published the same day. Note: the `v1` tag
still points at the Day 2 code — the release edit page offers no way to
move a tag, so `@v1` users still get the old rules until the tag is moved
with a git tag push (follow-up). Next: the next rule
set (e.g. Python error-handling rules), or a first check for another language.

Day 11 (15 Nov 2026): Python error-handling rules shipped (ERR001–ERR004,
10 new tests, 83 passing) — an `except` handler whose body is only `pass`
silently swallows the error, raising a new exception inside a handler without
`from` loses the original traceback (a bare re-raise and `raise ... from e`
or `from None` are left alone), catching `BaseException` also swallows
`KeyboardInterrupt` and `SystemExit`, and a `try` block whose body is only
`pass` does nothing. The checks are AST-based, so a nested handler's raise
is reported once, on the handler that owns it, and a raise inside a nested
function defined in a handler is not flagged. Dogfooded on real PR #10: the
action's own review comment flagged ERR001/ERR002/ERR003/ERR004 on the new
`examples/error-example.py` fixture (plus the expected TST001), and the PR
was merged with all 3 checks green. Release v1.4 published the same day.
Note: the `v1` tag still points at the Day 2 code — the release edit page
offers no way to move a tag, so `@v1` users still get the old rules until
the tag is moved with a git tag push (follow-up). Next: the next rule set,
or a first check for another language.

Day 12 (16 Nov 2026): Python security rules shipped (SEC101–SEC105, 11 new tests, 94 passing) — a subprocess call given a string command instead of a list, os.popen() which always runs through the shell, the random module used to build a token/password/secret (use secrets instead), assert statements outside test code (stripped with python -O), tempfile.mktemp() with its predictable filenames, and os.chmod() with a world-writable mode. The checks are AST-based and best-effort by design: a variable holding the command cannot be checked, so only literal strings and f-strings are flagged for SEC101, and SEC102 only fires on a direct random.* call assigned to a sensitively-named variable. Dogfooded on real PR #11: the action's own review comment flagged SEC101 (three times), SEC102, SEC103, SEC104 and SEC105 on the new examples/security-example.py fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.5 published the same day. Note: the v1 tag still points at the Day 2 code — the release edit page offers no way to move a tag, so @v1 users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 13 (17 Nov 2026): Python bug rules shipped (BUG101–BUG105, 12 new tests, 106 passing) — code after `return` / `raise` / `break` / `continue` in the same block never runs, a dict literal with the same constant key twice silently overwrites the earlier value, `is` / `is not` with a literal number, string or bytes value compares identity instead of value, a constant `if` / `while` condition makes the branch always run or never run (`while True` is exempt as the standard infinite-loop idiom), and comparing a variable to itself (`x == x`) is almost certainly a typo. The checks are AST-based and best-effort by design: only statements in the same body list are checked for BUG101, so code after an `if` that returns is left alone, and BUG102 only compares constant keys. Dogfooded on real PR #12: the action's own review comment flagged BUG101 (twice), BUG102, BUG103 (twice), BUG104 (twice) and BUG105 on the new `examples/bug-example.py` fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.6 published the same day. Note: the `v1` tag still points at the Day 2 code — the release edit page offers no way to move a tag, so @v1 users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 14 (18 Nov 2026): Python performance rules shipped (PERF101–PERF105, 15 new tests, 121 passing) — string concatenation with `+=` inside a loop is quadratic (collect the parts and `''.join(...)` once), `range(len(x))` (iterate the sequence directly, or use `enumerate` when the index is needed), a membership test against a list literal scans the whole list on every check (use a set or frozenset), a loop whose body only appends to a fresh list is a list comprehension in disguise, and `for k in d.keys():` is redundant since iterating a dict already yields its keys. The checks are AST-based and best-effort by design: PERF101 only fires for names assigned a string literal in the same function, so `total += 1` on a number is left alone; PERF103 only flags list literals, not tuples or variables; PERF104 only fires when the list was assigned `[]` in the same function. Dogfooded on real PR #13: the action's own review comment flagged PERF101, PERF102, PERF103, PERF104 and PERF105 on the new `examples/perf-example.py` fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.7 published the same day. Note: the `v1` tag still points at the Day 2 code — the release edit page offers no way to move a tag, so @v1 users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 15 (19 Nov 2026): Python documentation rules shipped (DOC101–DOC105, 12 new tests, 133 passing) — a public function or method without a docstring, a public class without a docstring, a docstring that is empty or only whitespace, a docstring whose summary line does not end with a full stop, and a TODO / FIXME / XXX marker inside a docstring. The checks are AST-based and best-effort by design: private and dunder names are exempt, as are `test_*` functions and `Test*` classes, which are self-documenting by convention. Dogfooded on real PR #14: the action's own review comment flagged DOC101, DOC102, DOC103, DOC104 and DOC105 on the new `examples/doc-example.py` fixture (plus BUG003 on the TODO line and the expected TST001), and the PR was merged with all 3 checks green. Release v1.8 published the same day. Note: the `v1` tag still points at the Day 2 code — the release edit page offers no way to move a tag, so `@v1` users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 16 (20 Nov 2026): Python type-hint rules shipped (TYP101–TYP105, 15 new tests, 148 passing) — a public function or method without a return type annotation, an unannotated parameter (self/cls exempt), a bare `Any` annotation that switches the type checker off, a deprecated `typing.List` / `Dict` / `Set` / `Tuple` / `FrozenSet` / `Type` generic (use the builtin generics instead), and a function annotated `-> None` that returns a value. The checks are AST-based and best-effort by design: private, dunder and `test_*` functions are exempt from TYP101/TYP102, as are stub bodies and `@overload` / `@abstractmethod` definitions, and TYP104 only recognises bare `List` / `Dict` / ... spellings when the same fragment imports them from `typing`. Dogfooded on real PR #15: the action's own review comment flagged TYP101, TYP102, TYP103, TYP104 (twice) and TYP105 on the new `examples/typing-example.py` fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.9 published the same day. Note: the `v1` tag still points at the Day 2 code — the release edit page offers no way to move a tag, so `@v1` users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 17 (21 Nov 2026): Python async/concurrency rules shipped (ASC101–ASC105, 10 new tests, 158 passing) — `time.sleep()` inside an `async def` blocks the whole event loop (use `await asyncio.sleep(...)` instead), calling an async function without `await` builds a coroutine that never runs, an `async def` that never awaits anything is probably a plain function in disguise, `loop.run_until_complete(...)` inside an `async def` raises because the loop is already running, and a bare `asyncio.create_task(...)` statement drops the task handle so the task can be garbage-collected mid-flight and its exceptions lost. The checks are AST-based and best-effort by design: ASC102 only recognises async functions defined in the same fragment (plus `asyncio.sleep`), calls passed to `create_task` / `ensure_future` / `gather` / `run_until_complete` / `wait` are exempt because they schedule the coroutine on purpose, and stub bodies (including a docstring plus `pass` / `...`) and async generators are exempt from ASC103. Dogfooded on real PR #16: the action's own review comment flagged ASC101, ASC102, ASC103, ASC104 and ASC105 on the new `examples/async-example.py` fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.10 published the same day. Note: the `v1` tag still points at the Day 2 code — the release edit page offers no way to move a tag, so `@v1` users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 18 (22 Nov 2026): Python idiom rules shipped (IDM101–IDM105, 11 new tests, 169 passing) — `open()` outside a `with` statement leaks the file handle (use `with open(...) as f:` so it closes even on error), `type(x) == T` compares the exact type and misses subclasses (use `isinstance(x, T)`), `len(x) == 0` / `!= 0` / `> 0` is the long way of writing `not x` / `x`, old-style `"...%s..." % value` formatting is superseded by f-strings and `str.format()`, and `x in d.keys()` is redundant since membership in a dict already tests its keys. The checks are AST-based and best-effort by design: only the direct `with open(...) as f:` form exempts IDM101 (a handle opened earlier and closed by hand is still flagged), and only the bare `open` / `type` / `len` names are recognised. Dogfooded on real PR #17: the action's own review comment flagged IDM101, IDM102, IDM103 (twice), IDM104 and IDM105 on the new `examples/idiom-example.py` fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.11 published the same day. Note: the `v1` tag still points at the Day 2 code — the release edit page offers no way to move a tag, so `@v1` users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 19 (23 Nov 2026): Python logging rules shipped (LOG101–LOG105, 11 new tests, 180 passing) — a logging call that formats its message eagerly with `%` builds the string even when the level is disabled (pass the values as arguments instead), an f-string message has the same problem, `logging.exception()` outside an `except` handler has no active exception to log (use `logging.error(...)` or move the call into a handler), a message built with `str.format(...)` is eager formatting too, and `logging.warn()` is deprecated in favour of `logging.warning()`. The checks are AST-based and best-effort by design: only calls of the form `<name>.<level>(...)` are recognised, where `<name>` is a bare name such as `logging` or `logger`, and a function defined inside an `except` handler counts as outside it for LOG103. Dogfooded on real PR #18: the action's own review comment flagged LOG101, LOG102, LOG103, LOG104 and LOG105 on the new `examples/logging-example.py` fixture (plus IDM104 on the `%` line and the expected TST001), and the PR was merged with all 3 checks green. Release v1.12 published the same day. Note: the `v1` tag still points at the Day 2 code — the release edit page offers no way to move a tag, so `@v1` users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 20 (24 Nov 2026): Python class-design rules shipped (CLS101–CLS105, 13 new tests, 193 passing) — a class that defines attributes but no methods is only a data container (use a @dataclass or a NamedTuple), an __init__ that only passes its arguments through to super().__init__() adds nothing (delete it), a method that never uses self does not need an instance (make it a @staticmethod), a class that defines __eq__ without __hash__ makes its instances unhashable, and a class whose body is only a docstring and/or pass is an empty placeholder. The checks are AST-based and best-effort by design: CLS103 counts a zero-argument super() call as using self, stub methods, dunder methods and @staticmethod / @classmethod / @property / @abstractmethod methods are exempt from CLS103, and CLS102 only fires when every argument passed to super() is one of the __init__ parameters. Dogfooded on real PR #19: the action's own review comment flagged CLS101, CLS102, CLS103, CLS104 and CLS105 on the new examples/class-example.py fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.13 published the same day. Note: the v1 tag still points at the Day 2 code — the release edit page offers no way to move a tag, so @v1 users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 21 (25 Nov 2026): Python function-design rules shipped (FN101–FN105, 15 new tests, 208 passing) — a function that returns a value on some paths but falls off the end or returns bare on others hands callers None by accident (return an explicit value on every path), a parameter that is never read misleads callers about what the function needs (remove it), a return with a value inside a generator is silently discarded (yield the value instead), a nested function that is never called is dead code (delete it or call it), and a default argument that is a function call is evaluated once when the function is defined, so every call shares the same object (use None as the default and call the function inside the body). The checks are AST-based and best-effort by design: FN101 treats a trailing if/else whose branches both return as returning, FN102 counts a parameter as used if its name is loaded anywhere in the function including inside a nested function, and FN102 skips self/cls, *args/**kwargs and stub/@overload/@abstractmethod functions. Dogfooded on real PR #20: the action's own review comment flagged FN101, FN102, FN103, FN104 and FN105 on the new examples/function-example.py fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.14 published the same day. Note: the v1 tag still points at the Day 2 code — the release edit page offers no way to move a tag, so @v1 users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 22 (26 Nov 2026): Python string rules shipped (STR101–STR105, 13 new tests, 221 passing) — an f-string with no placeholders is just a plain string with a needless f prefix (drop the prefix), a pure string method called as a bare statement such as name.strip() builds a new string and throws it away because strings are immutable (assign or return the result), str() called on a string literal is redundant (use the literal directly), two string literals joined with + should be merged into one literal, and .join() called on a single string such as ','.join('abc') joins it character by character (pass a list of strings instead). The checks are AST-based and best-effort by design: STR102 recognises the method name only, since the receiver's type cannot be known from a diff fragment, and STR105 only flags a literal argument, not a variable that happens to hold a string. Dogfooded on real PR #21: the action's own review comment flagged STR101, STR102, STR103, STR104 and STR105 on the new examples/string-example.py fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.15 published the same day. Note: the v1 tag still points at the Day 2 code — the release edit page offers no way to move a tag, so @v1 users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 23 (27 Nov 2026): Python return-value rules shipped (RET101–RET105, 13 new tests, 234 passing) — the result of .sort() or .reverse() used as a value is always None because both work in place (call them on their own line, or use sorted() / reversed()), and the same trap applies to the in-place list mutators .append(), .extend(), .insert(), .remove() and .clear(), to .update() merging a dict or set in place, to .shuffle() shuffling a list in place, and to the set mutators .add() and .discard(). The checks are AST-based and best-effort by design: a call standing alone as a bare statement is exempt since the in-place change is the point there, the method name alone is recognised since the receiver's type cannot be known from a diff fragment, and RET104 only recognises the attribute form random.shuffle(...), not a bare shuffle(...) from a from-import. Dogfooded on real PR #22: the action's own review comment flagged RET101, RET102, RET103, RET104 and RET105 on the new examples/return-example.py fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.16 published the same day. Note: the v1 tag still points at the Day 2 code — the release edit page offers no way to move a tag, so @v1 users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

Day 24 (28 Nov 2026): Python dictionary rules shipped (DCT101–DCT105, 14 new tests, 248 passing) — d[key] if key in d else default looks the key up twice (use d.get(key, default)), the same lookup written as an if/else assigning d[key] on one branch and a default on the other is the same one-liner, if key not in d: d[key] = default inserts a default by hand (use d.setdefault(key, default)), dict() with no arguments is the empty dict in longhand (use {}), and d[key] = d[key] + 1 states the update the long way (use d[key] += 1, or collections.Counter for counting). The checks are AST-based and best-effort by design: the dict and key are matched by name and expression shape only, since their types cannot be known from a diff fragment, DCT102 only recognises a single assignment on each branch, and DCT105 only fires when the right-hand side is a binary operation on the very same subscript. Dogfooded on real PR #23: the action's own review comment flagged DCT101, DCT102, DCT103, DCT104 and DCT105 on the new examples/dict-example.py fixture (plus the expected TST001), and the PR was merged with all 3 checks green. Release v1.17 published the same day. Note: the v1 tag still points at the Day 2 code — the release edit page offers no way to move a tag, so @v1 users still get the old rules until the tag is moved with a git tag push (follow-up). Next: the next rule set, or a first check for another language.

## License

MIT — see [LICENSE](LICENSE).
