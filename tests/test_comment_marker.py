"""Tests for the comment-marker feature.

A custom marker lets two workflows review the same PR without overwriting
each other's comment: each run only finds (and updates) the comment that
carries its own marker. Run with: python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import main as main_module  # noqa: E402
from src.report import MARKER, make_marker, render_report  # noqa: E402


class TestMakeMarker(unittest.TestCase):
    def test_default_marker_unchanged(self):
        self.assertEqual(make_marker(), MARKER)
        self.assertEqual(make_marker(""), MARKER)
        self.assertEqual(MARKER, "<!-- ai-pr-reviewer -->")

    def test_named_marker_is_namespaced(self):
        self.assertEqual(make_marker("dogfood"), "<!-- ai-pr-reviewer:dogfood -->")

    def test_marker_name_is_sanitised(self):
        # Spaces, slashes and comment-closers are stripped, so a marker can
        # never break out of its HTML comment.
        self.assertEqual(make_marker("my workflow"), "<!-- ai-pr-reviewer:myworkflow -->")
        self.assertEqual(make_marker("a/b-->c"), "<!-- ai-pr-reviewer:ab-c -->")

    def test_marker_name_truncated_and_empty_falls_back(self):
        self.assertEqual(make_marker("x" * 100), f"<!-- ai-pr-reviewer:{'x' * 40} -->")
        self.assertEqual(make_marker("-->"), MARKER)
        self.assertEqual(make_marker("   "), MARKER)


class TestRenderReportMarker(unittest.TestCase):
    def test_report_uses_custom_marker_as_first_line(self):
        body = render_report([], "owner/repo", 1, marker=make_marker("dogfood"))
        self.assertTrue(body.startswith("<!-- ai-pr-reviewer:dogfood -->"))
        self.assertNotIn(MARKER + "\n", body)

    def test_report_defaults_to_plain_marker(self):
        body = render_report([], "owner/repo", 1)
        self.assertTrue(body.startswith(MARKER + "\n"))


class TestFindExistingCommentMarker(unittest.TestCase):
    """find_existing_comment must only match comments carrying its marker."""

    def setUp(self):
        self._real_request = main_module._github_request

    def tearDown(self):
        main_module._github_request = self._real_request

    def _stub_comments(self, comments):
        def fake_request(method, url, token, payload=None):
            if method == "GET" and "comments" in url:
                # First page carries the comments; later pages are empty,
                # matching the real paginated API. (Check the trailing
                # "&page=N" — "page=1" also appears inside "per_page=100".)
                return comments if url.endswith("&page=1") else []
            return {}
        main_module._github_request = fake_request

    def test_finds_only_the_matching_marker(self):
        self._stub_comments([
            {"id": 111, "body": "<!-- ai-pr-reviewer -->\n## 🤖 AI PR Review — #9"},
            {"id": 222, "body": "<!-- ai-pr-reviewer:dogfood -->\n## 🤖 AI PR Review — #9"},
        ])
        self.assertEqual(
            main_module.find_existing_comment("o/r", 9, "tok", make_marker("dogfood")), 222)
        self.assertEqual(
            main_module.find_existing_comment("o/r", 9, "tok", MARKER), 111)

    def test_returns_none_when_no_comment_carries_the_marker(self):
        self._stub_comments([
            {"id": 111, "body": "<!-- ai-pr-reviewer -->\n## 🤖 AI PR Review — #9"},
        ])
        self.assertIsNone(
            main_module.find_existing_comment("o/r", 9, "tok", make_marker("dogfood")))

    def test_update_targets_the_marked_comment(self):
        calls = []
        self._stub_comments([
            {"id": 111, "body": "<!-- ai-pr-reviewer -->\nold default comment"},
            {"id": 222, "body": "<!-- ai-pr-reviewer:dogfood -->\nold dogfood comment"},
        ])
        real = main_module._github_request

        def recording_request(method, url, token, payload=None):
            calls.append((method, url))
            return real(method, url, token, payload)

        main_module._github_request = recording_request
        main_module.post_or_update_comment(
            "o/r", 9, "tok", "new body", marker=make_marker("dogfood"))
        self.assertIn(("PATCH", "https://api.github.com/repos/o/r/issues/comments/222"), calls)
        self.assertNotIn(("PATCH", "https://api.github.com/repos/o/r/issues/comments/111"), calls)


if __name__ == "__main__":
    unittest.main()
