"""Render review findings as a Markdown PR comment.

The report is designed to be posted once per PR (the action updates the
same comment on re-runs, keyed by a hidden marker). It starts with a short
verdict, then a table of counts, then the findings grouped by severity.
"""

from __future__ import annotations

import re

from .checks import Finding

MARKER = "<!-- ai-pr-reviewer -->"

# Characters allowed inside a custom marker name. Anything else is dropped,
# so a marker can never break out of its HTML comment or collide with the
# default marker by accident.
_MARKER_SAFE = re.compile(r"[^A-Za-z0-9_-]")
_MAX_MARKER_LEN = 40


def make_marker(name: str = "") -> str:
    """Build the hidden HTML comment that keys a review comment.

    The default (no name) is ``<!-- ai-pr-reviewer -->``. A name gives a
    namespaced marker, e.g. ``make_marker("dogfood")`` returns
    ``<!-- ai-pr-reviewer:dogfood -->``, so two workflows reviewing the
    same PR each keep their own comment instead of overwriting each other.
    Unsafe characters are stripped and an empty result falls back to the
    default marker.
    """
    clean = _MARKER_SAFE.sub("", (name or "").strip())[:_MAX_MARKER_LEN]
    # Collapse runs of "-" and drop leading/trailing ones, so the name can
    # never contain "--" and break out of its HTML comment.
    clean = re.sub(r"-+", "-", clean).strip("-")
    if not clean:
        return MARKER
    return f"<!-- ai-pr-reviewer:{clean} -->"

_SEVERITY_LABEL = {
    "error": "🔴 Error",
    "warning": "🟡 Warning",
    "info": "🔵 Info",
}


def verdict(findings: list[Finding]) -> str:
    """One-line verdict: errors block, warnings advise caution, else clean."""
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    if errors:
        return f"❌ {errors} blocking issue{'s' if errors != 1 else ''} found — please fix before merging."
    if warnings:
        return f"⚠️ No blocking issues, but {warnings} warning{'s' if warnings != 1 else ''} worth a look."
    return "✅ No issues found — looks good to merge."


def render_report(findings: list[Finding], repo: str, pr_number: int,
                  marker: str = MARKER) -> str:
    """Render the full Markdown comment body for a PR review."""
    lines = [marker, f"## 🤖 AI PR Review — #{pr_number}", "", verdict(findings), ""]
    if not findings:
        lines.append("Static checks found no security issues, bug patterns, "
                     "complexity problems or missing tests in the added lines.")
        lines.append("")
        lines.append("_Reviewed by [ai-pr-reviewer-action]"
                     f"(https://github.com/{repo}) — static analysis only; "
                     "an AI summary is added when a Groq key is provided._")
        return "\n".join(lines)

    counts = {sev: sum(1 for f in findings if f.severity == sev)
              for sev in ("error", "warning", "info")}
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for sev in ("error", "warning", "info"):
        lines.append(f"| {_SEVERITY_LABEL[sev]} | {counts[sev]} |")
    lines.append("")

    for severity in ("error", "warning", "info"):
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        lines.append(f"### {_SEVERITY_LABEL[severity]}")
        lines.append("")
        for finding in group:
            location = f"`{finding.path}`"
            if finding.line:
                location += f":{finding.line}"
            lines.append(f"- **{finding.rule}** {location} — {finding.message}")
            if finding.suggestion:
                lines.append(f"  - _Fix: {finding.suggestion}_")
        lines.append("")

    lines.append("---")
    lines.append("_Reviewed by [ai-pr-reviewer-action]"
                 f"(https://github.com/{repo}) — static analysis only; "
                 "an AI summary is added when a Groq key is provided._")
    return "\n".join(lines)
