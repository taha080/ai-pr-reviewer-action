"""Parse a unified diff into per-file added lines with new-file line numbers.

Only the standard library is used so the action runs anywhere Python 3.9+
is available. The parser is deliberately small: it understands the hunk
headers (``@@ -a,b +c,d @@``), file headers (``diff --git`` / ``+++ b/...``)
and added/removed/context lines. Binary files and renames are skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_DIFF_RE = re.compile(r"^diff --git a/(.*) b/(.*)$")
_NEW_FILE_RE = re.compile(r"^\+\+\+ b/(.*)$")


@dataclass
class AddedLine:
    """One added line, with its line number in the new version of the file."""

    lineno: int
    text: str


@dataclass
class ChangedFile:
    """One file touched by the diff, with its added lines only."""

    path: str
    added: list[AddedLine] = field(default_factory=list)
    deleted: bool = False

    @property
    def new_text(self) -> str:
        """The added lines joined as text (handy for quick scans)."""
        return "\n".join(line.text for line in self.added)


def parse_unified_diff(diff_text: str) -> list[ChangedFile]:
    """Parse ``diff_text`` and return the changed files in diff order."""
    files: list[ChangedFile] = []
    current: ChangedFile | None = None
    new_lineno = 0

    for raw in diff_text.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("diff --git "):
            match = _DIFF_RE.match(line)
            path = match.group(2) if match else line.rsplit(" b/", 1)[-1]
            current = ChangedFile(path=path)
            files.append(current)
            new_lineno = 0
            continue
        if line.startswith("+++ "):
            match = _NEW_FILE_RE.match(line)
            if match and current is not None and current.path != match.group(1):
                current.path = match.group(1)
            continue
        if line.startswith("--- "):
            continue
        if line.startswith("Binary files "):
            if current is not None:
                files.pop()
            current = None
            continue
        if current is None:
            continue

        hunk = _HUNK_RE.match(line)
        if hunk:
            new_lineno = int(hunk.group(1))
            continue
        if line.startswith("@@"):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            current.added.append(AddedLine(lineno=new_lineno, text=line[1:]))
            new_lineno += 1
        elif line.startswith("-") and not line.startswith("---"):
            # Removed lines do not advance the new-file line number.
            continue
        elif line.startswith("\\"):
            # "\ No newline at end of file" — no line number change.
            continue
        else:
            # Context line: present in both versions.
            new_lineno += 1

    return [f for f in files if f.added or f.deleted]


def parse_patch(patch: str, path: str) -> ChangedFile:
    """Parse a single-file patch (as returned by the GitHub files API)."""
    parsed = parse_unified_diff(
        f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n{patch}"
    )
    if parsed:
        return parsed[0]
    return ChangedFile(path=path)
