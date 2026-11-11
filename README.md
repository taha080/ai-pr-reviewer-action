# ai-pr-reviewer-action

Free, open-source GitHub Action that reviews PR diffs for **security issues,
bug patterns, complexity and missing tests** — static analysis first, with an
optional AI summary when you bring your own Groq key (BYOK). No paid service,
no data stored anywhere.

## What it checks

| Category | Examples |
| --- | --- |
| Security | Hardcoded credentials, `eval()` / `exec()`, shell injection (`shell=True`, `os.system`), unsafe `pickle` / `yaml.load`, weak hashes, disabled TLS verification |
| Bugs | Bare `except:`, silent `except Exception:`, mutable default arguments, `TODO` / `FIXME` markers, string-built queries |
| Complexity | Functions over 50 lines, over 5 arguments, nesting deeper than 3 levels, more than 5 returns, boolean flag parameters, nested or over-long comprehensions, lambdas assigned to a variable (Python AST: CPL001–CPL007; JS/TS via brace tracking) |
| JavaScript / TypeScript | Leftover `console.log`, `debugger`, `var`, loose `==` / `!=`, `document.write`, `innerHTML` assignment, `parseInt` without a radix, blocking dialogs, `new Function()`, `: any` types, `eval()`, string timers, `with` statement, direct `document.cookie` access, comparator-less `.sort()`, long functions, too many parameters, deep nesting (JS011–JS018) |
| Tests | Source files changed with no test file touched in the PR |
| Style | Lines over 120 characters, leftover `print()` calls |

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
to report without failing.

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

## License

MIT — see [LICENSE](LICENSE).
