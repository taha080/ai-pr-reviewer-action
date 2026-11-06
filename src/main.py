"""Entry point for the ai-pr-reviewer-action composite action.

Reads its inputs from environment variables (GitHub passes action inputs
as ``INPUT_<NAME>``), fetches the PR diff through the GitHub REST API with
the provided token, runs the static checks, posts (or updates) a review
comment, and exits non-zero when blocking findings exist and
``fail-on`` says so.

Optional AI summary: if ``INPUT_GROQ_API_KEY`` is set, the findings plus a
short diff excerpt are sent to Groq (BYOK — the key is never stored or
logged) and the model's summary is appended to the comment. Without a key
the action still works fully on static analysis alone.

Only the standard library is used; no dependencies to install.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.checks import review_files  # noqa: E402
from src.diffparse import ChangedFile, parse_patch  # noqa: E402
from src.report import MARKER, render_report, verdict  # noqa: E402

GITHUB_API = "https://api.github.com"
GROQ_API = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"
DEFAULT_MAX_FINDINGS = 30


def _github_request(method: str, url: str, token: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:500]
        raise RuntimeError(f"GitHub API {method} {url} failed ({exc.code}): {detail}") from exc


def get_pr_files(repo: str, pr_number: int, token: str) -> list[ChangedFile]:
    """Fetch the PR's changed files (paginated) and parse each patch."""
    files: list[ChangedFile] = []
    page = 1
    while True:
        page_data = _github_request(
            "GET", f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/files?per_page=100&page={page}", token
        )
        if not isinstance(page_data, list) or not page_data:
            break
        for item in page_data:
            patch = item.get("patch")
            if not patch:
                continue  # binary / too large — nothing to review line by line
            files.append(parse_patch(patch, item["filename"]))
        page += 1
    return files


def find_existing_comment(repo: str, pr_number: int, token: str) -> int | None:
    """Return the id of our previous review comment, if one exists."""
    page = 1
    while True:
        comments = _github_request(
            "GET",
            f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}",
            token,
        )
        if not isinstance(comments, list) or not comments:
            return None
        for comment in comments:
            if MARKER in comment.get("body", ""):
                return comment["id"]
        page += 1


def post_or_update_comment(repo: str, pr_number: int, token: str, body: str) -> None:
    """Create the review comment, or update the existing one in place."""
    existing = find_existing_comment(repo, pr_number, token)
    if existing:
        _github_request(
            "PATCH", f"{GITHUB_API}/repos/{repo}/issues/comments/{existing}",
            token, {"body": body},
        )
    else:
        _github_request(
            "POST", f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments",
            token, {"body": body},
        )


def groq_summary(findings_text: str, diff_excerpt: str, api_key: str) -> str | None:
    """Ask Groq for a short plain-language summary of the findings."""
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {
                "role": "system",
                "content": ("You review pull requests. Summarise the findings below in "
                            "3-5 short bullet points a busy reviewer can act on. "
                            "Do not invent issues that are not listed."),
            },
            {
                "role": "user",
                "content": f"Findings:\n{findings_text}\n\nDiff excerpt:\n{diff_excerpt}",
            },
        ],
        "temperature": 0.2,
        "max_tokens": 400,
    }
    request = urllib.request.Request(GROQ_API, data=json.dumps(payload).encode(), method="POST")
    request.add_header("Authorization", f"Bearer {api_key}")
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read())
        return data["choices"][0]["message"]["content"].strip()
    except Exception as exc:  # AI summary is best-effort; never fail the run
        print(f"::warning::Groq summary skipped: {exc}", file=sys.stderr)
        return None


def _set_output(name: str, value: str) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")
    print(f"{name}={value}")


def main() -> int:
    token = os.environ.get("INPUT_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    groq_key = os.environ.get("INPUT_GROQ_API_KEY", "")
    fail_on = os.environ.get("INPUT_FAIL_ON", "error").lower()
    try:
        max_findings = int(os.environ.get("INPUT_MAX_FINDINGS", DEFAULT_MAX_FINDINGS))
    except ValueError:
        max_findings = DEFAULT_MAX_FINDINGS

    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    pr_number = 0
    if event_path and os.path.exists(event_path):
        with open(event_path, encoding="utf-8") as handle:
            event = json.load(handle)
        pr_number = int(event.get("pull_request", {}).get("number") or event.get("number") or 0)
    pr_number = int(os.environ.get("INPUT_PR_NUMBER") or pr_number or 0)

    if not token or not repo or not pr_number:
        print("::error::Missing GITHUB_TOKEN, GITHUB_REPOSITORY or PR number.", file=sys.stderr)
        print("Run this action on pull_request events with a github-token input.", file=sys.stderr)
        return 2

    files = get_pr_files(repo, pr_number, token)
    findings = review_files(files)[:max_findings]
    body = render_report(findings, repo, pr_number)

    if groq_key:
        findings_text = "\n".join(
            f"- [{f.severity}] {f.rule} {f.path}:{f.line} {f.message}" for f in findings
        ) or "No findings."
        excerpt = "\n".join(f.new_text for f in files)[:4000]
        summary = groq_summary(findings_text, excerpt, groq_key)
        if summary:
            body += f"\n\n### 🧠 AI summary (Groq, BYOK)\n\n{summary}\n"

    post_or_update_comment(repo, pr_number, token, body)

    _set_output("findings", str(len(findings)))
    _set_output("errors", str(sum(1 for f in findings if f.severity == "error")))
    _set_output("verdict", verdict(findings))

    if fail_on == "error" and any(f.severity == "error" for f in findings):
        return 1
    if fail_on == "warning" and any(f.severity in ("error", "warning") for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
