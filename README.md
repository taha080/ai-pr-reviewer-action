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

## License

MIT — see [LICENSE](LICENSE).
