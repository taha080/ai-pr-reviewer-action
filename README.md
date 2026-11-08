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
| Complexity | Functions over 50 lines, over 5 arguments, nesting deeper than 3 levels (Python AST; JS/TS via brace tracking) |
| JavaScript / TypeScript | Leftover `console.log`, `debugger`, `var`, loose `==` / `!=`, `document.write`, `innerHTML` assignment, `parseInt` without a radix, blocking dialogs, `new Function()`, `: any` types, long functions, too many parameters, deep nesting (JS011–JS013) |
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
- `src/checks_js.py` — the JavaScript / TypeScript rule set (JS001–JS013).
- `src/report.py` — renders the Markdown review comment.
- `src/main.py` — fetches the diff, runs the checks, posts/updates the comment.

The repo dogfoods itself: `.github/workflows/dogfood.yml` runs the action
from the PR's own checkout (`uses: ./`) on every pull request, and
`examples/bad-example.js` is a fixture with deliberately flagged code so
each rule change can be verified against a real review comment.

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

## License

MIT — see [LICENSE](LICENSE).
